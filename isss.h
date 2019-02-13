/************************************************************************
* Filename:   isss.h
* Author:     Anunay Chandra (Cypherock)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding shamir secret sharing
              scheme using the mnemonic phrase as a secret and diving it
              into "N" shares and recreating the secret by using at least
              "T" shares via lagrange's interpolation.
*************************************************************************/

#ifndef ISSS_H
#define ISSS_H

/************************** HEADER FILES ***************************/
#include <iostream>

/*************************** NAMESPACE ***************************/
using namespace std;

/*************************** DATATYPES ***************************/
typedef unsigned char byte;

/*************************** VARIABLES ***************************/
static byte N_mnemonics;
static byte threshold;

/***********************FUNCTION DECLARATIONS ***************************/
void convert_to_byteArray(string mphrases[], byte secrets[], byte n_mnemonics);
void create_shares(byte secrets[], byte n, byte k, byte **shares);
bool has_sufficient_shares(byte x);
void extract_secret(byte **r_shares, string secrets[]);

#endif