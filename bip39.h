/************************************************************************
* Filename:   bip39.h
* Author:     Anunay Chandra (Cypherock)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding BIP39 implementation.
              This BIP describes the implementation of a mnemonic code or 
              mnemonic sentence -- a group of easy to remember words -- 
              for the generation of deterministic wallets. It consists of 
              two parts: generating the mnemonic, and converting 
              it into a binary seed. This seed can be later used to 
              generate deterministic wallets using BIP32 or similar 
              methods.
*************************************************************************/

#ifndef BIP39_H
#define BIP39_H

/*************************** HEADER FILES ***************************/

#include <iostream>
#include <stdlib.h>
#include "sha256.h"
#include "wordlist.h"

/**************************** NAMESPACE ****************************/
using namespace std;

/*********************** FUNCTION DEFINITIONS **********************/

void generate_index_array(string main_string, uint16_t index_array[])
{
    for (uint8_t i = 0; i < len(index_array) * 11; i += 11)
    {
        index_array[i / 11] = 0;
        uint8_t x = 10;
        for (uint8_t j = i; j < i + 11 && j < len(index_array) * 11; j++)
        {
            if (main_string[j] == '1')
            {
                index_array[i / 11] += (1 << x);
            }

            x--;
        }
    }
}

void convert_to_mnemonic(string phrases[], uint16_t index_array[])
{
    for (uint8_t i = 0; i < len(index_array); i++)
    {
        phrases[i] = wordlist[index_array[i]];
    }
}

void generatePhrase(string phrases[], uint8_t n_phrases)
{

    if (n_phrases == 12)
    {
        uint8_t ENT[16];
        for (uint8_t i = 0; i < 16; i++)
        {
            ENT[i] = random() % 256;
        }

        uint8_t *hash = new uint8_t[SHA256_BLOCK_SIZE];

        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, ENT, 16);
        sha256_final(&ctx, hash);

        string padding = "";
        while (hash[0] > 0)
        {
            if ((hash[0] & 1))
            {
                padding = "1" + padding;
            }
            else
            {
                padding = "0" + padding;
            }

            hash[0] = hash[0] >> 1;
        }

        for (uint8_t i = 0; i < 4; i++)
        {
            padding.pop_back();
        }

        string main_string = "";
        for (uint8_t i = 0; i < 132; i++)
        {
            string temp_string = "";
            uint8_t count = count_bits(ENT[i]);
            while (ENT[i] > 0)
            {
                if ((ENT[i] & 1) == 0)
                {
                    temp_string = "0" + temp_string;
                }
                else
                {
                    temp_string = "1" + temp_string;
                }

                ENT[i] = ENT[i] >> 1;
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

        main_string += padding;
        uint16_t index_array[12];
        generate_index_array(main_string, index_array);
        convert_to_mnemonic(phrases, index_array);
    }
    else if (n_phrases == 18)
    {
        uint8_t ENT[24];
        for (uint8_t i = 0; i < 16; i++)
        {
            ENT[i] = random() % 256;
        }

        uint8_t *hash = new uint8_t[SHA256_BLOCK_SIZE];

        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, ENT, 24);
        sha256_final(&ctx, hash);

        string padding = "";
        while (hash[0] > 0)
        {
            if ((hash[0] & 1))
            {
                padding = "1" + padding;
            }
            else
            {
                padding = "0" + padding;
            }

            hash[0] = hash[0] >> 1;
        }

        for (uint8_t i = 0; i < 2; i++)
        {
            padding.pop_back();
        }

        string main_string = "";
        for (uint8_t i = 0; i < 198; i++)
        {
            string temp_string = "";
            uint8_t count = count_bits(ENT[i]);
            while (ENT[i] > 0)
            {
                if ((ENT[i] & 1) == 0)
                {
                    temp_string = "0" + temp_string;
                }
                else
                {
                    temp_string = "1" + temp_string;
                }

                ENT[i] = ENT[i] >> 1;
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

        main_string += padding;
        uint16_t index_array[18];
        generate_index_array(main_string, index_array);
        convert_to_mnemonic(phrases, index_array);
    }
    else
    {
        uint8_t ENT[32];
        for (uint8_t i = 0; i < 32; i++)
        {
            ENT[i] = random() % 256;
        }

        uint8_t *hash = new uint8_t[SHA256_BLOCK_SIZE];

        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, ENT, 32);
        sha256_final(&ctx, hash);

        string padding = "";
        while (hash[0] > 0)
        {
            if ((hash[0] & 1))
            {
                padding = "1" + padding;
            }
            else
            {
                padding = "0" + padding;
            }

            hash[0] = hash[0] >> 1;
        }
        string main_string = "";
        for (uint16_t i = 0; i < 264; i++)
        {
            string temp_string = "";
            uint8_t count = count_bits(ENT[i]);
            while (ENT[i] > 0)
            {
                if ((ENT[i] & 1) == 0)
                {
                    temp_string = "0" + temp_string;
                }
                else
                {
                    temp_string = "1" + temp_string;
                }

                ENT[i] = ENT[i] >> 1;
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

        main_string += padding;
        uint16_t index_array[24];
        generate_index_array(main_string, index_array);
        convert_to_mnemonic(phrases, index_array);
    }
}

#endif