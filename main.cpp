/*********************************************************************
* Filename:   main.cpp
* Author:     Anunay Chandra (Cypherock)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    This code is used to perform the user-defined tests on
              shamir secret sharing and BIP39 implementations. This code 
              also serves as example usage of the functions.
*********************************************************************/

/******************** HEADER FILES ***************************/
#include <iostream>
#include <stdio.h>
#include "isss.h"
#include "bip39.h"
#include <string>
#include <stdint.h>

/********************* NAMESPACE ***************************/
using namespace std;

int main()
{
    while (true)
    {
        cout << "Enter 1 to generate the mnemonic phrase" << endl;
        cout << "Enter 2 to create the shares " << endl;
        cout << "Enter 3 to recreate the secret " << endl;
        cout << "Enter 4 to exit" << endl;
        uint8_t choice;
        cin >> choice;

        cout << endl
             << endl;
        if (choice == 1)
        {
            cout << "Enter the number of words you want to generate " << endl;
            uint8_t n_words;
            cin >> n_words;
            string phrase[n_words];
            generatePhrase(phrase, n_words);

            cout << "Phrase Generated... " << endl;
            cout << endl;

            cout << "Generated phrase is" << endl;
            for (uint8_t i = 0; i < n_words; i++)
            {
                cout << phrase[i] << " ";
            }
            cout << endl;
        }
        else if (choice == 2)
        {
            cout << "Enter the number of words in the mnemonic phrase " << endl;
            uint8_t n_words;
            cin >> n_words;
            string phrase[n_words];
            for (uint8_t i = 0; i < n_words; i++)
            {
                cout << "Enter word "
                     << " " << (i + 1) << " : ";
                cin >> phrase[i];
                cout << endl;
            }

            if (n_words == 12)
            {
                uint8_t secret[17];
                convert_to_byteArray(phrase, secret, n_words);
                uint8_t n, k;
                cout << "Enter the number of shares you want to generate " << endl;
                cin >> n;
                cout << "Enter the minimum number of shares needed to recreate the secret " << endl;
                cin >> k;

                uint8_t **shares = new uint8_t *[n];
                for (uint8_t i = 0; i < n; i++)
                {
                    shares[i] = new uint8_t[26];
                }

                create_shares(secret, n, k, shares);

                for (uint8_t i = 0; i < n; i++)
                {
                    cout << "Share " << (i + 1) << " : ";
                    for (uint8_t j = 0; j < 26; j++)
                    {
                        cout << shares[i][j] << " ";
                    }

                    cout << endl;
                }
            }
            else if (n_words == 18)
            {
                uint8_t secret[25];
                convert_to_byteArray(phrase, secret, n_words);
                uint8_t n, k;
                cout << "Enter the number of shares you want to generate " << endl;
                cin >> n;
                cout << "Enter the minimum number of shares needed to recreate the secret " << endl;
                cin >> k;

                uint8_t **shares = new uint8_t *[n];
                for (uint8_t i = 0; i < n; i++)
                {
                    shares[i] = new uint8_t[34];
                }

                create_shares(secret, n, k, shares);

                for (uint8_t i = 0; i < n; i++)
                {
                    cout << "Share " << (i + 1) << " : ";
                    for (uint8_t j = 0; j < 34; j++)
                    {
                        cout << shares[i][j] << " ";
                    }

                    cout << endl;
                }
            }
            else
            {
                uint8_t secret[33];
                convert_to_byteArray(phrase, secret, n_words);
                uint8_t n, k;
                cout << "Enter the number of shares you want to generate " << endl;
                cin >> n;
                cout << "Enter the minimum number of shares needed to recreate the secret " << endl;
                cin >> k;

                uint8_t **shares = new uint8_t *[n];
                for (uint8_t i = 0; i < n; i++)
                {
                    shares[i] = new uint8_t[42];
                }

                create_shares(secret, n, k, shares);

                for (uint8_t i = 0; i < n; i++)
                {
                    cout << "Share " << (i + 1) << " : ";
                    for (uint8_t j = 0; j < 42; j++)
                    {
                        cout << shares[i][j] << " ";
                    }

                    cout << endl;
                }
            }
        }
        else if (choice == 3)
        {
            cout << endl
                 << endl;

        label:
            cout << "Enter the recovery share 1 " << endl;
            string share1;
            cin >> share1;
            uint8_t temp[share1.length()];
            uint16_t j = 0;
            for (uint8_t i = 0; i < share1.length(); i++)
            {
                if (share1[i] != ' ')
                {
                    j++;
                }
                else
                {
                    temp[j] = temp[j] * 10 + (share1[i] - 48);
                }
            }

            uint8_t id[6];
            uint8_t threshold = share1[6];
            uint8_t padding = share1[7];

            for (uint8_t i = 0; i < 6; i++)
            {
                id[i] = temp[i];
            }

            if (padding == 4)
            {
                uint8_t **rshares = new uint8_t *[threshold];
                for (uint8_t i = 0; i < threshold; i++)
                {
                    rshares[i] = new uint8_t[26];
                }
                for (uint8_t i = 0; i < 26; i++)
                {
                    rshares[0][i] = temp[i];
                }

                for (uint8_t i = 1; i < threshold; i++)
                {
                    cout << "Enter " << threshold - i << " more shares" << endl;
                    for (uint8_t j = 0; j < 26; j++)
                    {
                        cin >> rshares[i][j];
                    }

                    for (uint8_t j = 0; j < 6; j++)
                    {
                        if (rshares[i][j] != id[j])
                        {
                            cout << "Invalid share" << endl;
                            cout << "Enter the shares again" << endl;
                            goto label;
                        }
                    }
                }

                string secret[12];

                extract_secret(rshares, secret);

                for (uint8_t i = 0; i < 12; i++)
                {
                    cout << secret[i] << " ";
                }
            }
            else if (padding == 2)
            {
                uint8_t **rshares = new uint8_t *[threshold];
                for (uint8_t i = 0; i < threshold; i++)
                {
                    rshares[i] = new uint8_t[34];
                }

                for (uint8_t i = 0; i < 34; i++)
                {
                    rshares[0][i] = temp[i];
                }
                for (uint8_t i = 1; i < threshold; i++)
                {
                    cout << "Enter " << threshold - i << " more shares" << endl;
                    for (uint8_t j = 0; j < 34; j++)
                    {
                        cin >> rshares[i][j];
                    }

                    for (uint8_t j = 0; j < 6; j++)
                    {
                        if (rshares[i][j] != id[j])
                        {
                            cout << "Invalid share" << endl;
                            cout << "Enter the shares again" << endl;
                            goto label;
                        }
                    }
                }

                string secret[18];

                extract_secret(rshares, secret);

                for (uint8_t i = 0; i < 18; i++)
                {
                    cout << secret[i] << " ";
                }
            }
            else
            {
                uint8_t **rshares = new uint8_t *[threshold];
                for (uint8_t i = 0; i < threshold; i++)
                {
                    rshares[i] = new uint8_t[42];
                }

                for (uint8_t i = 0; i < 42; i++)
                {
                    rshares[0][i] = temp[i];
                }
                for (uint8_t i = 1; i < threshold; i++)
                {
                    cout << "Enter " << threshold - i << " more shares" << endl;
                    for (uint8_t j = 0; j < 42; j++)
                    {
                        cin >> rshares[i][j];
                    }

                    for (uint8_t j = 0; j < 6; j++)
                    {
                        if (rshares[i][j] != id[j])
                        {
                            cout << "Invalid share" << endl;
                            cout << "Enter the shares again" << endl;
                            goto label;
                        }
                    }
                }

                string secret[24];

                extract_secret(rshares, secret);

                for (uint8_t i = 0; i < 24; i++)
                {
                    cout << secret[i] << " ";
                }
            }
        }
        else
        {
            return 0;
        }
    }
}