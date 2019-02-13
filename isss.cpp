/*********************************************************************
* Filename:   isss.cpp
* Author:     Anunay Chandra (Cypherock)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Implementation of the shamir secret sharing scheme on 
              BIP39 mnemonic phrases used in deterministic wallets.
              This implementation uses SHA256 hashing algorithm and 
              galois field(256) arithematic.
*********************************************************************/

/************************ HEADER FILES ***************************/
#include <iostream>
#include "isss.h"
#include "gf256.h"
#include "wordlist.h"
#include "sha256.h"

/************************** NAMESPACE ***************************/
using namespace std;

/************************** DATATYPES ***************************/
static const uint16_t prime = 256;

/********************* FUNCTION DEFINITIONS ***************************/
byte Power(byte a, uint16_t x)
{
    byte result = 1;

    // Multiply the result in galois field(256) x times.
    for (byte i = 0; i < x; i++)
    {
        result = mul(result, a);
    }

    return result;
}

void encode_secret(string mphrases[], uint16_t data[], byte n_mnemonics)
{
    for (int i = 0; i < n_mnemonics; i++)
    {
        for (int j = 0; j < 2048; j++)
        {
            // matches the words present in the mnemonic recovery seed with
            // the BIP39 english wordlist.
            if (mphrases[i] == wordlist[j])
            {
                data[i] = j;
                break;
            }
        }
    }
}

void convert_to_byteArray(string mphrases[], byte secrets[], byte n_mnemonics)
{
    N_mnemonics = n_mnemonics;
    uint16_t *data = new uint16_t[n_mnemonics];
    encode_secret(mphrases, data, n_mnemonics);

    string main_string = "";
    for (byte i = 0; i < n_mnemonics; i++)
    {
        byte count = count_bits(data[i]);
        string temp_string = "";
        while (data[i] > 0)
        {
            if ((data[i] & 1) == 0)
            {
                temp_string = "0" + temp_string;
            }
            else
            {
                temp_string = "1" + temp_string;
            }

            data[i] = data[i] >> 1;
        }

        while (count < 11)
        {
            temp_string = "0" + temp_string;
            count++;
        }

        main_string = main_string + temp_string;
    }

    uchar dummy[main_string.length()];
    for (uint16_t i = 0; i < main_string.length(); i++)
    {
        dummy[i] = main_string[i];
    }
    SHA256_CTX ctx;
    byte buff[SHA256_BLOCK_SIZE];
    sha256_init(&ctx);
    sha256_update(&ctx, dummy, 12 * 11);
    sha256_final(&ctx, buff);
    string padding = "";
    byte bit_count = count_bits(buff[0]);
    while (buff[0] > 0)
    {
        if ((data[0] & 1))
        {
            padding = "1" + padding;
        }
        else
        {
            padding = "0" + padding;
        }

        buff[0] = buff[0] >> 1;
    }

    while (bit_count < 8)
    {
        padding = "0" + padding;
        bit_count++;
    }

    if (n_mnemonics == 12)
    {
        for (byte i = 0; i < 4; i++)
        {
            padding.pop_back();
        }

        main_string += padding;

        for (byte i = 0; i < 12 * 11 + 4; i += 8)
        {
            secrets[i / 8] = 0;
            byte x = 7;
            for (byte j = i; j < i + 8 && j < 12 * 11 + 4; j++)
            {
                if (main_string[j] == '1')
                {
                    secrets[i / 8] += (1 << x);
                }

                x--;
            }
        }
    }
    else if (n_mnemonics == 18)
    {
        for (byte i = 0; i < 6; i++)
        {
            padding.pop_back();
        }

        main_string += padding;

        for (byte i = 0; i < 18 * 11 + 2; i += 8)
        {
            secrets[i / 8] = 0;
            byte x = 7;
            for (byte j = i; j < i + 8 && j < 18 * 11 + 2; j++)
            {
                if (main_string[j] == '1')
                {
                    secrets[i / 8] += (1 << x);
                }

                x--;
            }
        }
    }
    else
    {
        for (uint16_t i = 0; i < 24 * 11; i += 8)
        {
            secrets[i / 8] = 0;
            byte x = 7;
            for (uint16_t j = i; j < i + 8 && j < 24 * 11; j++)
            {
                if (main_string[j] == '1')
                {
                    secrets[i / 8] += (1 << x);
                }

                x--;
            }
        }
    }
}

void create_shares(byte secrets[], byte n, byte k, byte **shares)
{
    threshold = k;

    if (N_mnemonics == 12)
    {
        byte **coeff = new byte *[k];
        for (byte i = 0; i < k; i++)
        {
            coeff[i] = new byte[17];
        }

        for (byte i = 0; i < 17; i++)
        {

            coeff[0][i] = secrets[i];
            for (int j = 1; j < k; j++)
            {
                coeff[j][i] = rand() % prime;
            }
        }

        for (byte i = 0; i < n; i++)
        {
            for (byte j = 0; j < 6; j++)
            {
                shares[i][j] = rand() % prime;
            }

            shares[i][6] = threshold;
            shares[i][7] = 4;
            shares[i][8] = (i + 1);
            for (byte j = 9; j < 26; j++)
            {
                shares[i][j] = coeff[0][j];
                for (int x = 1; x < k; x++)
                {

                    byte temp = Power(byte(i + 1), x);
                    shares[i][j] = add(shares[i][j + 1], mul(coeff[x][j], temp));
                }
            }
        }
    }
    else if (N_mnemonics == 18)
    {
        byte **coeff = new byte *[k];
        for (byte i = 0; i < k; i++)
        {
            coeff[i] = new byte[25];
        }

        for (byte i = 0; i < 25; i++)
        {

            coeff[0][i] = secrets[i];
            for (int j = 1; j < k; j++)
            {
                coeff[j][i] = rand() % prime;
            }
        }

        for (byte i = 0; i < n; i++)
        {
            for (byte j = 0; j < 6; j++)
            {
                shares[i][j] = rand() % prime;
            }

            shares[i][6] = threshold;
            shares[i][7] = 2;
            shares[i][8] = (i + 1);
            for (byte j = 9; j < 34; j++)
            {
                shares[i][j] = coeff[0][j];
                for (int x = 1; x < k; x++)
                {

                    byte temp = Power(byte(i + 1), x);
                    shares[i][j] = add(shares[i][j + 1], mul(coeff[x][j], temp));
                }
            }
        }
    }
    else
    {
        byte **coeff = new byte *[k];
        for (byte i = 0; i < k; i++)
        {
            coeff[i] = new byte[33];
        }

        for (byte i = 0; i < 33; i++)
        {

            coeff[0][i] = secrets[i];
            for (int j = 1; j < k; j++)
            {
                coeff[j][i] = rand() % prime;
            }
        }

        for (byte i = 0; i < n; i++)
        {
            for (byte j = 0; j < 6; j++)
            {
                shares[i][j] = rand() % prime;
            }

            shares[i][6] = threshold;
            shares[i][7] = 2;
            shares[i][8] = (i + 1);
            for (byte j = 9; j < 42; j++)
            {
                shares[i][j] = coeff[0][j];
                for (int x = 1; x < k; x++)
                {

                    byte temp = Power(byte(i + 1), x);
                    shares[i][j] = add(shares[i][j + 1], mul(coeff[x][j], temp));
                }
            }
        }
    }
}

bool has_sufficient_shares(byte x)
{
    return x >= threshold;
}

void back_to_original_array(byte byte_array[], uint16_t middle_array[], byte padding)
{

    if (padding == 4)
    {
        string main_string = "";
        for (byte i = 0; i < 17; i++)
        {
            string temp_string = "";
            int count = count_bits(byte_array[i]);
            while (byte_array[i] > 0)
            {
                if ((byte_array[i] & 1) == 0)
                {
                    temp_string = "0" + temp_string;
                }
                else
                {
                    temp_string = "1" + temp_string;
                }

                byte_array[i] = byte_array[i] >> 1;
            }

            if (count != 8)
            {
                while (count < 8)
                {
                    temp_string = "0" + temp_string;
                    count++;
                }
            }

            main_string = main_string + temp_string;
        }

        for (byte i = 0; i < padding; i++)
        {
            main_string.pop_back();
        }

        for (byte i = 0; i < 12 * 11; i += 11)
        {
            middle_array[i / 11] = 0;
            byte x = 10;
            for (byte j = i; j < i + 11 && j < 12 * 11; j++)
            {
                if (main_string[j] == '1')
                {
                    middle_array[i / 11] += (1 << x);
                }

                x--;
            }
        }
    }
    else if (padding == 2)
    {
        string main_string = "";
        for (byte i = 0; i < 25; i++)
        {
            string temp_string = "";
            byte count = count_bits(byte_array[i]);
            while (byte_array[i] > 0)
            {
                if ((byte_array[i] & 1) == 0)
                {
                    temp_string = "0" + temp_string;
                }
                else
                {
                    temp_string = "1" + temp_string;
                }

                byte_array[i] = byte_array[i] >> 1;
            }

            if (count != 8)
            {
                while (count < 8)
                {
                    temp_string = "0" + temp_string;
                    count++;
                }
            }

            main_string = main_string + temp_string;
        }

        for (byte i = 0; i < padding; i++)
        {
            main_string.pop_back();
        }

        for (byte i = 0; i < 18 * 11; i += 11)
        {
            middle_array[i / 11] = 0;
            byte x = 10;
            for (byte j = i; j < i + 11 && j < 18 * 11; j++)
            {
                if (main_string[j] == '1')
                {
                    middle_array[i / 11] += (1 << x);
                }

                x--;
            }
        }
    }
    else
    {
        string main_string = "";
        for (byte i = 0; i < 33; i++)
        {
            string temp_string = "";
            int count = count_bits(byte_array[i]);
            while (byte_array[i] > 0)
            {
                if ((byte_array[i] & 1) == 0)
                {
                    temp_string = "0" + temp_string;
                }
                else
                {
                    temp_string = "1" + temp_string;
                }

                byte_array[i] = byte_array[i] >> 1;
            }

            if (count != 8)
            {
                while (count < 8)
                {
                    temp_string = "0" + temp_string;
                    count++;
                }
            }

            main_string = main_string + temp_string;
        }

        for (byte i = 0; i < padding; i++)
        {
            main_string.pop_back();
        }

        for (uint16_t i = 0; i < 24 * 11; i += 11)
        {
            middle_array[i / 11] = 0;
            byte x = 10;
            for (uint16_t j = i; j < i + 11 && j < 24 * 11; j++)
            {
                if (main_string[j] == '1')
                {
                    middle_array[i / 11] += (1 << x);
                }

                x--;
            }
        }
    }
}

void recover_phrase(uint16_t middle_array[], string secrets[])
{
    for (byte i = 0; i < len(middle_array); i++)
    {
        secrets[i] = wordlist[middle_array[i]];
    }
}

void extract_secret(byte **r_shares, string secrets[])
{
    if (r_shares[0][7] == 4)
    {
        byte temp[25][r_shares[0][6]][2];
        for (byte i = 8; i < 25; i++)
        {
            for (byte j = 0; j < r_shares[0][6]; j++)
            {
                temp[i][j][0] = byte(r_shares[j][8]);
                temp[i][j][1] = byte(r_shares[j][i + 1]);
            }
        }

        byte byte_array[17];
        byte x = 0;
        for (byte i = 0; i < 17; i++)
        {
            byte secret = 0;
            for (byte j = 0; j < r_shares[0][6]; j++)
            {
                byte num = 1;
                byte den = 1;

                for (byte k = 0; k < r_shares[0][6]; k++)
                {
                    if (j != k)
                    {
                        num = mul(num, sub(x, temp[i][k][0]));
                        den = mul(den, sub(temp[i][j][0], temp[i][k][0]));
                    }
                }

                int value = temp[i][j][1];

                secret = add(secret, mul(value, div(num, den)));
            }
            secret = (secret + prime) % prime;
            byte_array[i] = secret;
        }

        uint16_t middle_array[12];
        back_to_original_array(byte_array, middle_array, 4);
        recover_phrase(middle_array, secrets);
    }
    else if (r_shares[0][7] == 2)
    {
        byte temp[33][r_shares[0][6]][2];
        for (byte i = 8; i < 33; i++)
        {
            for (byte j = 0; j < r_shares[0][6]; j++)
            {
                temp[i][j][0] = byte(r_shares[j][8]);
                temp[i][j][1] = byte(r_shares[j][i + 1]);
            }
        }

        byte byte_array[25];
        byte x = 0;
        for (byte i = 0; i < 25; i++)
        {
            byte secret = 0;
            for (byte j = 0; j < r_shares[0][6]; j++)
            {
                byte num = 1;
                byte den = 1;

                for (byte k = 0; k < r_shares[0][6]; k++)
                {
                    if (j != k)
                    {
                        num = mul(num, sub(x, temp[i][k][0]));
                        den = mul(den, sub(temp[i][j][0], temp[i][k][0]));
                    }
                }

                int value = temp[i][j][1];

                secret = add(secret, mul(value, div(num, den)));
            }
            secret = (secret + prime) % prime;
            byte_array[i] = secret;
        }

        uint16_t middle_array[18];
        back_to_original_array(byte_array, middle_array, 2);
        recover_phrase(middle_array, secrets);
    }
    else
    {
        byte temp[41][r_shares[0][6]][2];
        for (byte i = 8; i < 41; i++)
        {
            for (byte j = 0; j < r_shares[0][6]; j++)
            {
                temp[i][j][0] = byte(r_shares[j][8]);
                temp[i][j][1] = byte(r_shares[j][i + 1]);
            }
        }

        byte byte_array[33];
        byte x = 0;
        for (byte i = 0; i < 33; i++)
        {
            byte secret = 0;
            for (byte j = 0; j < r_shares[0][6]; j++)
            {
                byte num = 1;
                byte den = 1;

                for (byte k = 0; k < r_shares[0][6]; k++)
                {
                    if (j != k)
                    {
                        num = mul(num, sub(x, temp[i][k][0]));
                        den = mul(den, sub(temp[i][j][0], temp[i][k][0]));
                    }
                }

                int value = temp[i][j][1];

                secret = add(secret, mul(value, div(num, den)));
            }
            secret = (secret + prime) % prime;
            byte_array[i] = secret;
        }

        uint16_t middle_array[24];
        back_to_original_array(byte_array, middle_array, 0);
        recover_phrase(middle_array, secrets);
    }
}