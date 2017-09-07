/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdint.h>
#include <string.h>

#include "asinine/dsl.h"
#include "asinine/x509.h"
#include "internal/macros.h"
#include "internal/x509.h"

typedef asinine_err_t (*delegate_parser_t)(asn1_parser_t *, x509_pubkey_t *);

typedef struct {
	asn1_oid_t oid;
	x509_pubkey_algo_t algorithm;
	delegate_parser_t param_parser;
	delegate_parser_t pubkey_parser;
	bool broken_encoding;
} pubkey_lookup_t;

typedef struct {
	asn1_oid_t oid;
	x509_ecdsa_curve_t curve;
} curve_lookup_t;

static asinine_err_t parse_null_or_empty_params(
    asn1_parser_t *, x509_pubkey_t *);
static asinine_err_t parse_ecdsa_params(asn1_parser_t *, x509_pubkey_t *);

static asinine_err_t parse_rsa_pubkey(asn1_parser_t *, x509_pubkey_t *);
static asinine_err_t parse_ecdsa_pubkey(asn1_parser_t *, x509_pubkey_t *);

static const pubkey_lookup_t pubkey_algorithms[] = {
    {
        ASN1_OID(1, 2, 840, 113549, 1, 1, 1), X509_PUBKEY_RSA,
        &parse_null_or_empty_params, &parse_rsa_pubkey, false,
    },
    {
        ASN1_OID(1, 2, 840, 10045, 2, 1), X509_PUBKEY_ECDSA,
        &parse_ecdsa_params, &parse_ecdsa_pubkey, true,
    },
};

static const curve_lookup_t curves[] = {
    {ASN1_OID(1, 2, 840, 10045, 3, 1, 7), X509_ECDSA_CURVE_SECP256R1},
    {ASN1_OID(1, 3, 132, 0, 34), X509_ECDSA_CURVE_SECP384R1},
    {ASN1_OID(1, 3, 132, 0, 35), X509_ECDSA_CURVE_SECP521R1},

};

static const pubkey_lookup_t *
find_pubkey_algorithm(const asn1_oid_t *oid) {
	size_t i;
	for (i = 0; i < NUM(pubkey_algorithms); i++) {
		if (asn1_oid_cmp(oid, &(pubkey_algorithms[i].oid)) == 0) {
			return &pubkey_algorithms[i];
		}
	}

	return NULL;
}

asinine_err_t
x509_parse_pubkey(asn1_parser_t *parser, x509_pubkey_t *pubkey) {
	// SubjectPublicKeyInfo
	RETURN_ON_ERROR(asn1_push_seq(parser));

	// AlgorithmIdentifier
	RETURN_ON_ERROR(asn1_push_seq(parser));

	NEXT_TOKEN(parser);
	if (!asn1_is_oid(&parser->token)) {
		return ASININE_ERROR_INVALID;
	}

	asn1_oid_t oid;
	asn1_oid(&parser->token, &oid);

	const pubkey_lookup_t *result = find_pubkey_algorithm(&oid);
	if (result == NULL) {
		return ASININE_ERROR_UNSUPPORTED;
	}

	pubkey->algorithm = result->algorithm;

	RETURN_ON_ERROR(result->param_parser(parser, pubkey));

	// End of AlgorithmIdentifier
	RETURN_ON_ERROR(asn1_pop(parser));

	NEXT_TOKEN(parser);
	if (!asn1_is_bitstring(&parser->token)) {
		return ASININE_ERROR_INVALID;
	}

	if (result->broken_encoding) {
		// This is why we can't have nice things. Some idiot made it so
		// that ECDSA pubkeys are really bitstrings, but octet strings
		// stuffed into a bitstring.
		RETURN_ON_ERROR(result->pubkey_parser(parser, pubkey));
	} else {
		RETURN_ON_ERROR(asn1_force_push(parser));
		RETURN_ON_ERROR(result->pubkey_parser(parser, pubkey));
		RETURN_ON_ERROR(asn1_pop(parser));
	}

	// End of SubjectPublicKeyInfo
	return asn1_pop(parser);
}

static asinine_err_t
parse_null_or_empty_params(asn1_parser_t *parser, x509_pubkey_t *pubkey) {
	(void)pubkey;
	return _x509_parse_null_or_empty_args(parser);
}

static asinine_err_t
parse_rsa_pubkey(asn1_parser_t *parser, x509_pubkey_t *pubkey) {
	const asn1_token_t *token = &parser->token;

	pubkey->key.rsa = (x509_pubkey_rsa_t){0};

	RETURN_ON_ERROR(asn1_push_seq(parser));

	// modulus (n)
	NEXT_TOKEN(parser);
	if (!asn1_is_int(token)) {
		return ASININE_ERROR_INVALID;
	}

	RETURN_ON_ERROR(asn1_int(token, NULL));

	if ((token->data[0] & 0x80) != 0) {
		// Signed modulus is invalid
		return ASININE_ERROR_INVALID;
	}

	// TODO: Strip leading 0 byte?
	pubkey->key.rsa.n     = parser->token.data;
	pubkey->key.rsa.n_num = parser->token.length;

	// public exponent (e)
	NEXT_TOKEN(parser);
	if (!asn1_is_int(token)) {
		return ASININE_ERROR_INVALID;
	}

	asn1_word_t temp;
	RETURN_ON_ERROR(asn1_int(token, &temp));
	if (temp < 0) {
		return ASININE_ERROR_INVALID;
	}
	pubkey->key.rsa.e = (asn1_uword_t)temp;

	return asn1_pop(parser);
}

static x509_ecdsa_curve_t
find_curve(const asn1_oid_t *oid) {
	for (size_t i = 0; i < NUM(curves); i++) {
		if (asn1_oid_cmp(oid, &curves[i].oid) == 0) {
			return curves[i].curve;
		}
	}
	return X509_ECDSA_CURVE_INVALID;
}

static asinine_err_t
parse_ecdsa_params(asn1_parser_t *parser, x509_pubkey_t *pubkey) {
	pubkey->has_params         = false;
	pubkey->params.ecdsa_curve = X509_ECDSA_CURVE_INVALID;

	NEXT_TOKEN(parser);
	if (asn1_is_null(&parser->token)) {
		return ASININE_OK;
	}

	if (!asn1_is_oid(&parser->token)) {
		return ASININE_ERROR_INVALID;
	}

	asn1_oid_t oid;
	RETURN_ON_ERROR(asn1_oid(&parser->token, &oid));

	x509_ecdsa_curve_t curve = find_curve(&oid);
	if (curve == X509_ECDSA_CURVE_INVALID) {
		return ASININE_ERROR_UNSUPPORTED;
	}

	pubkey->params.ecdsa_curve = curve;
	return ASININE_OK;
}

static asinine_err_t
parse_ecdsa_pubkey(asn1_parser_t *parser, x509_pubkey_t *pubkey) {
	pubkey->key.ecdsa.point     = parser->token.data;
	pubkey->key.ecdsa.point_num = parser->token.length;
	return ASININE_OK;
}
