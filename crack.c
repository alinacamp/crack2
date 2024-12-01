#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!
char *tryWord(char *plaintext, char *hashFilename)
{
    // Hash the plaintext
    char *hash = md5(plaintext, strlen(plaintext));

    // Open the hash file
    FILE *hfile = fopen(hashFilename, "r");
    if (hfile == NULL)
    {
        perror("error opening hash file.\n");
        exit(1);
    }

    char lpne[HASH_LEN];
    
    // Loop through the hash file, one line at a time.
    while (fgets(lpne, HASH_LEN, hfile))
    {
        lpne[strcspn(lpne, "\n")] = '\0';
    
        // Attempt to match the hash from the file to the
        // hash of the plaintext.
        if (strcmp(hash, lpne) == 0)
        {
            fclose(hfile);
            return strdup(hash); 
        }       
    }


    // If there is a match, you'll return the hash.
    // If not, return NULL.

    // Before returning, do any needed cleanup:
    //   Close files?
    fclose(hfile);
    //   Free memory?

    // Modify this line so it returns the hash
    // that was found, or NULL if not found.
    return NULL;
}


int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    char *hashFilename = argv[1];
    char *dictFname = argv[2];

    // Open the dictionary file for reading.
    FILE *dictFile = fopen(dictFname, "r");
    if (dictFile == NULL)
    {
        perror("Error opening dictionary file.\n");
        exit(1);
    }

    char worm[PASS_LEN];
    int crackCount = 0;

    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    
    // If we got a match, display the hash and the word. For example:
    //   5d41402abc4b2a76b9719d911017c592 hello
    while (fgets(worm, PASS_LEN, dictFile))
    {
        worm[strcspn(worm, "\n")] = '\0';

        char *hash = tryWord(worm, hashFilename);

        if (hash != NULL)
        {
            printf("%s %s\n", hash, worm);
            free(hash); //free mallocd memory
            crackCount++;
        }
    }
    // Close the dictionary file.
    fclose(dictFile);

    // Display the number of hashes that were cracked.
    printf("%d hashes cracked.\n", crackCount);
    return 0;
    // Free up any malloc'd memory?
}

