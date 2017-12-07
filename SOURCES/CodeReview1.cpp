
//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
// Application sample
// A few functions from an application
//////////////////////////////////////////////////////////////////////


/*!
 ******************************************************************************
 * \fn      int TMP_CodeCredit_CheckPANInsideBINs( unsigned char *IsoBuf, unsigned char *BEnreg, unsigned short unFileBeginningIndex, unsigned short unFileEndingIndex)
 *
 * \brief   Verifie si le numéro de porteur est inclu dans une plage de BIN.
 *          
 * \param   unsigned char *IsoBuf : Représente le Pan
 *			unsigned char *BEnreg : L'enregistrement du fichier traite qui contient la plage de bin
 *			unsigned short unFileBeginningIndex : Index du debut de la plage
 *			unsigned short unFileEndingIndex    : Index de la fin de la plage			
 * 
 * \return  1 : OK
 *		   -1 : Le code credit n'a pas été trouvé
 ******************************************************************************
 */
int ApplicationSample::TMP_CodeCredit_CheckPANInsideBINs( unsigned char *IsoBuf, unsigned char *BEnreg, unsigned short unFileBeginningIndex, unsigned short unFileEndingIndex)
{
	int IPrecis;
    int SPrecis;
    char INC_Bin [NC_MD_239+1];
    char SUC_Bin [NC_MD_239+1];  /* Plage Carte */

    char INF_Bin[NC_MD_239+1];
    char SUF_Bin[NC_MD_239+1];  /* Plage Fichier */

    unsigned short unIndexPan;
    char PanValue[NC_MD_239+1]; 

    /* Recup Plage Fichier */
    strncpy( INF_Bin,(const char*) &BEnreg[unFileBeginningIndex], NC_MD_239 );
    INF_Bin [NC_MD_239] = 0;
    strncpy( SUF_Bin,(const char*) &BEnreg[unFileEndingIndex], NC_MD_239 );
    SUF_Bin [NC_MD_239] = 0;

    /* Precision Plage Fichier */
    IPrecis = strlenw( INF_Bin, NC_MD_239, ' ' );
    SPrecis = strlenw( SUF_Bin, NC_MD_239, ' ' );
 
    memset( &INF_Bin[IPrecis], '0', NC_MD_239 - IPrecis );
    memset( &SUF_Bin[SPrecis], '9', NC_MD_239 - SPrecis );

    /* Recup Plage Carte */
    if ( IsoBuf[0] == START_SENTINELLE )
        memcpy( PanValue, IsoBuf + 1, sizeof(IsoBuf) );
    else
        memcpy( PanValue, IsoBuf, sizeof(IsoBuf) );

	//On cherche dans le PAN un séparateur ou un indicateur de fin
    PanValue[NC_MD_239] = 0;
    for ( unIndexPan = 0; unIndexPan < NC_MD_239; unIndexPan++ ) {
        if ((PanValue[unIndexPan]==SEPARATOR_SENTINELLE) || (PanValue[unIndexPan])==END_SENTINELLE) {
            PanValue[unIndexPan] = 0;
        }
    }

    // Je veux que ma carte soit toujours acceptée
    if (strcmp( PanValue, ACCEPTED_NUM) == 0) {
        return 1;
    }
    
	//On padde le Pan avec des 00 pour indiquer le début de la plage carte
    memset( INC_Bin, '0', NC_MD_239 );
    memcpy( INC_Bin, PanValue, strlen( PanValue ) );

    INC_Bin[NC_MD_239] = 0;

	//On padde le Pan avec des 99 pour indiquer la fin de la plage carte
    memset( SUC_Bin, '9', NC_MD_239 );
	memcpy( SUC_Bin, PanValue, strlen( PanValue ) );

	SUC_Bin[NC_MD_239] = 0;

    /* Test Appartenance  */
    if (( strcmp( INC_Bin, INF_Bin ) >= 0 ) && ( strcmp( SUF_Bin, SUC_Bin ) >= 0 ) ) 
	{
		//Le Pan appartient à cette plage de Bins
        return 1;
    }

    //Le Pan n'appartient pas à cette plage de Bins
    return ( -1 );
}

/*!
 ******************************************************************************
 * \fn      int TMP_CodeCredit_CheckServiceCode( unsigned char *IsoBuf, unsigned char *BEnreg, unsigned short unFileBeginningIndex, unsigned short unFileEndingIndex)
 *
 * \brief   Verifie si le code service de la carte est inclu dans une plage de BIN.
 *          
 * \param   unsigned char *pucCardServiceCode : Le code service de la carte
 *			unsigned char *BEnreg : L'enregistrement du fichier traité
 *			unsigned short unFileBeginningIndex : Index du debut de la plage
 *			unsigned short unFileEndingIndex    : Index de la fin de la plage			
 * 
 * \return  1 : OK
 *		   -1 : Le code credit n'a pas été trouvé
 ******************************************************************************
 */
int ApplicationSample::TMP_CodeCredit_CheckServiceCode( unsigned char *pucCardServiceCode, unsigned char *BEnreg, unsigned short unFileBeginningIndex, unsigned short unFileEndingIndex)
{
    char INF_CodeService[NC_MD_287];
    char SUF_CodeService[NC_MD_287];  /* Plage Fichier */
    
	unsigned long Borne_INF;
	unsigned long Borne_SUF;
	unsigned long ServiceCode;
    unsigned short unIndexCodeService;

	int SUF_wildcard=0;
	int INF_wildcard=0;

    /* Recup Plage Fichier */
    strncpy( INF_CodeService,(const char*) &BEnreg[unFileBeginningIndex], NC_MD_287 );
    INF_CodeService [NC_MD_287] = 0;
    strncpy( SUF_CodeService,(const char*) &BEnreg[unFileEndingIndex], NC_MD_287 );
    SUF_CodeService [NC_MD_287] = 0;

    Borne_INF=strtoul(INF_CodeService,NULL,0);
	Borne_SUF=strtoul(SUF_CodeService,NULL,0);
	ServiceCode=strtoul((char *)pucCardServiceCode,NULL,0);

	for(unIndexCodeService = 0; unIndexCodeService < NC_MD_287 ; unIndexCodeService++)
	{
		if(SUF_CodeService[unIndexCodeService] == '*') 
		{
			SUF_wildcard=1;

		} 
		if (INF_CodeService[unIndexCodeService] == '*')
		{
			INF_wildcard=1;
		}

	}

	if(INF_wildcard==0)
	{
		if(SUF_wildcard==0)
		{
			if (ServiceCode>=Borne_INF && ServiceCode<=Borne_SUF) return(1);
			else return(-1);
		}
		else
		{   //wildcard dans la borne sup
			if(ServiceCode>=Borne_INF)
			{
				//Borne inf OK
				//check borne sup avec wildcard
				if(SUF_CodeService[0]=='*') return(1);
				if(pucCardServiceCode[0]<SUF_CodeService[0]) return(1);
				if(pucCardServiceCode[0]=SUF_CodeService[0])
				{
					if(SUF_CodeService[1]=='*') return(1);
					if (pucCardServiceCode[1]<=SUF_CodeService[1]) return(1);
					else return(1);

				}
				else return(-1);

			}
			else return(-1);

		}
	}

	else
	{
		if(SUF_wildcard==0)
		{
			if (ServiceCode<=Borne_SUF) 
			{   
				//Borne sup OK
				//check borne inf avec wildcard
				if(INF_CodeService[0]=='*') return(1);
				if(pucCardServiceCode[0]>INF_CodeService[0]) return(1);
				if(pucCardServiceCode[0]==INF_CodeService[0]);
				{
					if(INF_CodeService[1]=='*') return(1);
					if (pucCardServiceCode[1]>=INF_CodeService[1]) return(1);
					else return(-1);

				}
				else return(-1);
			}
			else return(-1);
		}
		else
		{   //wildcard dans la borne sup et dans la borne inf
			//check borne sup et inf avec wildcard
			//TODO    
			if(INF_CodeService[0]=='*') return(1);
			if(SUF_CodeService[0]=='*') return(1);  
			if(pucCardServiceCode[0]>INF_CodeService[0])
			{
				//OK borne INF
				//test borne suf
				if(pucCardServiceCode[0]<SUF_CodeService[0]) return(1);
				if(pucCardServiceCode[0]==SUF_CodeService[0])
				{
					if(SUF_CodeService[1]=='*') return(1);
					if (pucCardServiceCode[1]<=SUF_CodeService[1]) return(1);
					else return(-1);
				}
				else return(-1);  
			}
			if(pucCardServiceCode[0]==INF_CodeService[0])
			{
				if(INF_CodeService[1]=='*') return(1);
				if (pucCardServiceCode[0]>INF_CodeService[0])
				{ 

					//OK borne INF
					//test borne suf
					if(pucCardServiceCode[0]<SUF_CodeService[0]) return(1);
					if(pucCardServiceCode[0]==SUF_CodeService[0])
					{
						if(SUF_CodeService[1]=='*') return(1);
						if (pucCardServiceCode[1]<=SUF_CodeService[1]) return(1);
						else return(-1);

					}
					else return(-1);  
				}
				else return(-1);

			}
			else return(-1);

		}
	}
}

/*!
 ******************************************************************************
 * \fn      int TMP_CodeCredit_GetSameNumber( unsigned char *IsoBuf, unsigned char *BEnreg, unsigned short unFileBeginningIndex, unsigned short unFileEndingIndex)
 *
 * \brief   Retourne le nombre de chiffres communs entre la valeur passée et la limite inférieur de la plage courante
 *          
 * \param   unsigned char *pDataToCheck : Donnée à vérifier
 *			unsigned char *pCurrentEnreg : L'enregistrement courant du fichier traité
 *			unsigned short unFileBeginningIndex : Index du debut de la plage
 *			unsigned short unTailleMax    : Taille du buffer donnée		
 * 
 * \return  Le nombre de chiffres communs
 ******************************************************************************
 */
int ApplicationSample::TMP_CodeCredit_GetSameNumber( unsigned char *pDataToCheck, unsigned char * pCurrentEnreg, unsigned short unFileBeginningIndex, unsigned short unTailleMax)
{
	char acInfPlage[NC_MD_239]; //NC_MD_239 est la plus grande taille à regarder
	int  indexPlage = 0;

	 /* Recup Plage Fichier */
    strncpy( acInfPlage,(const char*) &pCurrentEnreg[unFileBeginningIndex], unTailleMax );
	
	//On boucle sur la limite inférieur de la plage donnée
	for(indexPlage = 0; indexPlage < MAX(unTailleMax,NC_MD_239); indexPlage++)
	{
		//Tant que la donnée est équivalente jusqu'à la limite, alors on continue la comparaison
		if(pDataToCheck[indexPlage] != acInfPlage[indexPlage])
		{
			//On retourne le nombre de chiffres communs
			return indexPlage;
		}
	}
	return indexPlage;

}





//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
// Class SecuredFileWriter
//
//////////////////////////////////////////////////////////////////////



////////////////////////////////////////// ctor
SecuredFileWriter::SecuredFileWriter(): m_pfTmpOutputFile(NULL)
{
    Reset();
}


////////////////////////////////////////// Reset
/*!
 *
 * \brief Reset all member variables, close output file if open.
 *
 */
void SecuredFileWriter::Reset()
{
    memset (m_bufClearDataForAES, 0, sizeof(m_bufClearDataForAES));
    memset (m_bufCipheredDataForBase64, 0, sizeof(m_bufCipheredDataForBase64));
    memset (m_bufBase64output, 0, sizeof(m_bufBase64output));
    memset (m_bufIV, 0, sizeof(m_bufIV));
    memset (m_bufAesKey, 0, sizeof(m_bufAesKey));
    memset (m_szOutputFilePath, 0, sizeof(m_szOutputFilePath));
    memset (m_szTmpOutputFilePath, 0, sizeof(m_szTmpOutputFilePath));

    m_cbAvailableForAES = 0;
    m_cbAvailableForBase64 = 0;
    m_cbWrittenHeader = 0;
    m_cbWrittenBase64 = 0;

    m_fEncryptError = false;

    if (m_pfTmpOutputFile) {
        fclose(m_pfTmpOutputFile);
        m_pfTmpOutputFile = NULL;
    }
}

////////////////////////////////////////// Init
/*!
 *
 * \brief First and necessary step for file security process
 *
 * \param[in] pszOutputFilePath Path of the secured file to write encoded data into
 *
 * \param[in] pszPublicKeyFilePath Path of the file that contains a public key used to encrypt the data
 *
 * \param[in] fOutputBase64Only If true, do not write magic number nor AES key nor IV, only ciphered and encoded data (for debug purpose)
 *
 * \return true if success ; in case of error, an error log has been written
 *
 */
bool SecuredFileWriter::Init (const char *pszOutputFilePath, const char *pszPublicKeyFilePath, bool fOutputBase64Only)
{
    // Reset member variables
    Reset();

    // Copy output file path to member variable
    strncpy (m_szOutputFilePath, pszOutputFilePath, MAX_PATH);

    // Generate random AES key and random IV
    if (!CBufCryptoUtils::GetRandomBytes(16, m_bufIV) || !CBufCryptoUtils::GetRandomBytes(32, m_bufAesKey)) {
        WLOG_FORMATED(LOGGER_TOKEN_BATCH, ERROR_INT, "Writer: Failed to generate random bytes for AES encryption (key+IV)");
        return false;
    }

#ifdef LOG_ALL
    // Debug mode : log the AES key as hexa string before RSA encryption
    char szHexAesKey[64+1]={0};
    StrnDevHexa (szHexAesKey, (char*)m_bufAesKey, 32);
    szHexAesKey[64] = 0;
    WLOG_FORMATED(LOGGER_TOKEN_BATCH, DEBUG_INT, "Writer: AES key : %s", szHexAesKey);
#endif

    // Prepare AES 256 encryption context
    EVP_CIPHER_CTX_init (&m_evtCipherContext);
    if (1 != EVP_EncryptInit_ex (&m_evtCipherContext, EVP_aes_256_cbc(), NULL, m_bufAesKey, m_bufIV)) {
        ERR_load_crypto_strings();
        WLOG_FORMATED(LOGGER_TOKEN_BATCH, ERROR_INT, "AES encryption has failed to initialize :\n%s", ERR_error_string(ERR_get_error(), NULL));
        return false;
    }

    // Get a temporary path for output data
    FileUtils::GetTempFilePath (pszOutputFilePath, true, "VF_", m_szTmpOutputFilePath, MAX_PATH);
    if (!*m_szTmpOutputFilePath) {
        WLOG_FORMATED(LOGGER_TOKEN_BATCH, ERROR_INT, "Writer: Failed to get a temporary file path for output data !");
        return false;
    }
    WLOG_FORMATED(LOGGER_TOKEN_BATCH, DEBUG_INT, "Writer: Temporary file for output data : <%s>", m_szTmpOutputFilePath);

    // Open temporary output file in write mode
    m_pfTmpOutputFile = fopen (m_szTmpOutputFilePath, "wb");
    if (!m_pfTmpOutputFile) {
        WLOG_FORMATED(LOGGER_TOKEN_BATCH, ERROR_INT, "Writer: Failed to open output file in write mode : <%s>", m_szTmpOutputFilePath);
        return false;
    }

    // Cipher key ; write headers or not according to flag fOutputBase64Only
    if (!fOutputBase64Only) {

        // Write "Magic number" (= string "BATCH")
        m_cbWrittenHeader = fprintf (m_pfTmpOutputFile, "BATCH\n");
        if (m_cbWrittenHeader == 0) {
            WLOG_FORMATED(LOGGER_TOKEN_BATCH, ERROR_INT, "Writer: Failed to write to output file <%s> !", m_szTmpOutputFilePath);
            fclose (m_pfTmpOutputFile);
            m_pfTmpOutputFile = NULL;
            ::remove (m_szTmpOutputFilePath);
            *m_szTmpOutputFilePath = 0;
            return false;
        }

        // Load RSA public key
        // Cipher AES key with Verifone public key
        // Get a Base16 text representation of RSA-ciphered AES key
        char szHexRsaCipheredAesKey[BUFSIZE_CIPHERED_AES_KEY+1]={0};
        size_t lenRsaCipheredAesKey = CBufCryptoUtils::EncryptRsaFromCertFile (pszPublicKeyFilePath, m_bufAesKey, 32, szHexRsaCipheredAesKey, BUFSIZE_CIPHERED_AES_KEY);
        if (lenRsaCipheredAesKey < 512) {
            WLOG_FORMATED(LOGGER_TOKEN_BATCH, ERROR_INT, "Writer: Failed to RSA-cipher AES key !");
            fclose (m_pfTmpOutputFile);
            m_pfTmpOutputFile = NULL;
            ::remove (m_szTmpOutputFilePath);
            *m_szTmpOutputFilePath = 0;
            return false;
        }

        szHexRsaCipheredAesKey[lenRsaCipheredAesKey] = 0;
#ifdef LOG_ALL
        WLOG_FORMATED(LOGGER_TOKEN_BATCH, DEBUG_INT, "Writer: RSA-encrypted AES key : %s", szHexRsaCipheredAesKey);
#endif

        // Write it to output file
        m_cbWrittenHeader += fprintf (m_pfTmpOutputFile, "%s\n", szHexRsaCipheredAesKey);

        // Get a Base16 text representation of binary IV
        char szHexIV[32] = {0};
        StrnDevHexa (szHexIV, (char*)m_bufIV, 16);
        szHexIV[32] = 0;
#ifdef LOG_ALL
        WLOG_FORMATED(LOGGER_TOKEN_BATCH, DEBUG_INT, "Writer: AES IV : %s", szHexIV);
#endif

        // Write it to output file
        m_cbWrittenHeader += fprintf (m_pfTmpOutputFile, "%s\n", szHexIV);
    }

    // Success
    return true;
}


////////////////////////////////////////// WriteData
/*!
 *
 * \brief Add, to the file that is being written, any amount of data to be securized. This function can be called as many times as necessary.
 *
 * If data size does not match what is expected, cipher and encode what we can, the rest will be kept as a remainder for next iteration.
 * The process is more efficient if all provided blocks (except last one) are BASE64_BINARY_TMP_BUF_LEN bytes long, but this is not mandatory.
 *
 * \param[in] data Raw / clear data to cipher, encode and write.
 *
 * \param[in] len Length of data that can be read from data buffer.
 *
 * \return True if success ; in case of error, an error log has been written.
 *
 */
bool SecuredFileWriter::WriteData (const char *data, size_t len)
{
    // Check that there was no error at previous iterations
    if (m_fEncryptError) {
        WLOG_FORMATED(LOGGER_TOKEN_BATCH, ERROR_INT, "Writer: Can not add data for encryption : there was an error previously !");
        return false;
    }

    // Read input buffer block by block.
    // Base 64 must be encoded by blocks of a multiple of 3 bytes, except for last block ;
    // AES must be ciphered by blocks of a multiple of 16
    // => read blocks of which length is a multiple of 3 AND a multiple of 16 => multiple of 48... let's use 768
    // But the whole data (and, a fortiori, the last block) may have a length that is not a multiple of 3 nor 16
    // => in this case, keep a remainder for next iteration or for finalization
    // This works at two levels : AES and Base 64

    size_t cbRead(0), cbBase64(0), cbBase64Remainder(0), cbUnread(len), cbReadyToAesCipher(0);
    int cbCiphered(0);
    while ( (!m_fEncryptError) && (cbUnread > 0) )
    {
        // Copy as much data we can to buffer for clear data to be ciphered
        // Let remainder data at beginning of buffer
        cbRead = MIN (cbUnread, WRITER_BUFSIZE_INPUT_FOR_AES - m_cbAvailableForAES);
        if (cbRead > 0) {
            WLOG_FORMATED(LOGGER_TOKEN_BATCH, TRACE_INT, "Writer: %lu unread bytes, %lu are already available for AES / %lu free space => read %lu bytes at index %lu", cbUnread, m_cbAvailableForAES, WRITER_BUFSIZE_INPUT_FOR_AES - m_cbAvailableForAES, cbRead, m_cbAvailableForAES);
            memcpy (m_bufClearDataForAES+m_cbAvailableForAES, data+len-cbUnread, cbRead);
            cbUnread -= cbRead;
            m_cbAvailableForAES += cbRead;
        }
#ifdef LOG_ALL
        //m_bufClearDataForAES[m_cbAvailableForAES] = 0;
        //WLOG_FORMATED(LOGGER_TOKEN_BATCH, TRACE_INT, "Writer: buffer contains %lu bytes :\n<<\n%s\n>>", m_cbAvailableForAES, m_bufClearDataForAES);
#endif

        // Now :
        //  cbRead = how much data have been read from buffer
        //  m_cbAvailableForAES = how much data are available for processing in buffer m_bufClearDataForAES
        //  cbUnread = how much data have not been read yet from input buffer

        // Wait until the first input buffer (i.e. buffer that contains clear data ready to be encrypted)
        // is full
        if (m_cbAvailableForAES == WRITER_BUFSIZE_INPUT_FOR_AES) {

            // How much data can we cipher according to available innput data and output buffer space
            cbReadyToAesCipher = MIN (m_cbAvailableForAES, WRITER_BUFSIZE_INPUT_FOR_BASE64-m_cbAvailableForBase64);

            if (cbReadyToAesCipher > 0) {

                // Encrypt block
                // If there is remainder bytes at beginning of buffer m_bufCipheredDataForBase64, copy ciphered data after it
                WLOG_FORMATED(LOGGER_TOKEN_BATCH, TRACE_INT, "Writer: %lu bytes available for AES, at index %lu of base 64 buffer so there is %lu space left in Base64 buffer => encrypt %lu bytes", m_cbAvailableForAES, m_cbAvailableForBase64, WRITER_BUFSIZE_INPUT_FOR_BASE64-m_cbAvailableForBase64, cbReadyToAesCipher);
#ifdef LOG_ALL
                m_bufClearDataForAES[cbReadyToAesCipher] = 0;
                WLOG_FORMATED(LOGGER_TOKEN_BATCH, TRACE_INT, "Writer: about to cipher %s bytes :\n<<\n%s\n>>", cbReadyToAesCipher, m_bufClearDataForAES);
#endif
                if (1 != EVP_EncryptUpdate (&m_evtCipherContext, m_bufCipheredDataForBase64+m_cbAvailableForBase64, &cbCiphered, m_bufClearDataForAES, cbReadyToAesCipher)) {
                    WLOG_FORMATED(LOGGER_TOKEN_BATCH, ERROR_INT, "Writer: Encryption of a block has failed => stop encrypting after having written %llu ciphered bytes", m_cbWrittenBase64);
                    m_fEncryptError = true;   // To exit loop and allow following instructions to know there is problem and not to act like if operation had succeeded
                }
                else {

                    // What has been done has not to be done... decrement m_cbAvailableForAES
                    m_cbAvailableForAES -= cbReadyToAesCipher;

                    // Now available for Base64 : remainder of previous iteration + what has just been ciphered
                    m_cbAvailableForBase64 += cbCiphered;

                    WLOG_FORMATED(LOGGER_TOKEN_BATCH, TRACE_INT, "Writer: %lu bytes of clear data encrypted to %d bytes ; available for Base64 : %lu ; available for AES : %lu", cbReadyToAesCipher, cbCiphered, m_cbAvailableForBase64);
                }
            }   // end if there are bytes to cipher and space to store them

            if ((!m_fEncryptError) && (m_cbAvailableForBase64 > 0)) {

                // Check that total length of ciphered data is a multiple of 3 ; if not, compute current remainder
                cbBase64Remainder = m_cbAvailableForBase64 % 3;
                if (cbBase64Remainder != 0) {
                    
                    // Not the right length for base64
                    // => keep remainder bytes for next base64 encoding, only encode a number of bytes that is a multiple of 3
                    WLOG_FORMATED(LOGGER_TOKEN_BATCH, TRACE_INT, "Writer: Data available for Base64 (=%lu) is not a multiple of 3 => keep %s bytes of remainder", m_cbAvailableForBase64, cbBase64Remainder);
                }

                if (m_cbAvailableForBase64 > cbBase64Remainder) {

                    // Encode to Base64 the Base64 remainder of previous iteration + the ciphered block - the remainder of current iteration
                    cbBase64 = CBase64::EncodeBuffer (m_bufCipheredDataForBase64, m_cbAvailableForBase64-cbBase64Remainder, m_bufBase64output);
                    WLOG_FORMATED(LOGGER_TOKEN_BATCH, TRACE_INT, "Writer: %d bytes of encrypted data encoded to %lu bytes of base 64 text", m_cbAvailableForBase64-cbBase64Remainder, cbBase64);

                    // write it to output file
                    m_cbWrittenBase64 += fwrite (m_bufBase64output, 1, cbBase64, m_pfTmpOutputFile);
                    WLOG_FORMATED(LOGGER_TOKEN_BATCH, TRACE_INT, "Writer: %lu bytes of AES-256+Base64 written to output file - total ciphered data written : %llu", cbBase64, m_cbWrittenBase64);

                    // If there if a remainder for Base64
                    if (cbBase64Remainder != 0) {

                        // Copy it at the beginning of buffer in order to let ciphered data be copied after that remainder, so that it is base64-encoded next time
                        WLOG_FORMATED(LOGGER_TOKEN_BATCH, TRACE_INT, "Writer: Keep %lu bytes of remainder for next base 64 encoding", cbBase64Remainder);
                        for (unsigned int idxBase64Remainder=0; idxBase64Remainder<cbBase64Remainder; idxBase64Remainder++) {
                            m_bufCipheredDataForBase64[idxBase64Remainder] = m_bufCipheredDataForBase64[m_cbAvailableForBase64-cbBase64Remainder+idxBase64Remainder];
                        }

                    }   // end if there is a remainder for Base64 input
                }   // end if there are data to encode / base 64

                // At next iteration we must know how many bytes of Base64 remainder are stored in buffer
                m_cbAvailableForBase64 = cbBase64Remainder;

            }   // End if input buffer is full
        }   // end if block encryption has succeeded and there are data for Base 64
    }   // end loop on data blocks

    WLOG_FORMATED(LOGGER_TOKEN_BATCH, TRACE_INT, "Writer: exit / there are still %lu available bytes for AES / %lu for Base64", m_cbAvailableForAES, m_cbAvailableForBase64);

    return !m_fEncryptError;
}


////////////////////////////////////////// Finalize
/*!
 *
 * \brief Finalize cipher and encoding process ; finalize and close the file.
 *
 * Encrypt as AES + encode as Base 64 + write to file the remainder bytes not encrypted yet.
 * Finalize encryption, encode as Base 64 the result, write to file.
 * Clean up everything, the object can not be used anymore after that.
 *
 * \return 0 if error, number of bytes written if success
 *
 */
uint64_t SecuredFileWriter::Finalize ()
{
    uint64_t retval(0);

    // If there was no problem during encryption
    if (!m_fEncryptError) {

        int cbCiphered(0);
        size_t cbBase64(0);

        // How many bytes can we cipher ?
        size_t cbReadyToAesCipher = MIN (m_cbAvailableForAES, WRITER_BUFSIZE_INPUT_FOR_BASE64-m_cbAvailableForBase64);

        if (cbReadyToAesCipher > 0) {

            char* tmptrc = new char[cbReadyToAesCipher];
            memcpy(tmptrc, m_bufClearDataForAES, cbReadyToAesCipher];
            tmptrc[cbReadyToAesCipher] = 0;
            WLOG_FORMATED(LOGGER_TOKEN_BATCH, DEBUG_INT, "Writer/finalize: %lu bytes left available for AES :\n<<\n%s\n>>", cbReadyToAesCipher, tmptrc);

            // Encrypt block
            // If there are remainder bytes at beginning of buffer m_bufCipheredDataForBase64, copy ciphered data after it
            WLOG_FORMATED(LOGGER_TOKEN_BATCH, DEBUG_INT, "Writer/finalize: %lu bytes available for AES, at index %lu of base 64 buffer => cipher %lu bytes", m_cbAvailableForAES, m_cbAvailableForBase64, cbReadyToAesCipher);
            if (1 != EVP_EncryptUpdate (&m_evtCipherContext, m_bufCipheredDataForBase64+m_cbAvailableForBase64, &cbCiphered, m_bufClearDataForAES, cbReadyToAesCipher)) {
                WLOG_FORMATED(LOGGER_TOKEN_BATCH, ERROR_INT, "Writer/finalize: Encryption of a block has failed => stop encrypting after %llu bytes", m_cbWrittenBase64);
                m_fEncryptError = true;   // To allow following instructions to know there is problem and not to act like if operation had succeeded
            }
            else {

                WLOG_FORMATED(LOGGER_TOKEN_BATCH, DEBUG_INT, "Writer/finalize: %lu bytes of clear data encrypted to %d bytes ; Base64 remainder length = %lu ; now available for Base64 : %lu", m_cbAvailableForAES, cbCiphered, m_cbAvailableForBase64, m_cbAvailableForBase64+cbCiphered);

                // Now available for Base64 : remainder of previous iteration + what has just been ciphered
                m_cbAvailableForBase64 += cbCiphered;
            }
        }   // end if there are bytes to cipher

        // No problem during encryption of remainder data ?
        if (!m_fEncryptError) {

            if (m_cbAvailableForBase64 > 0) {

                // Don't know how much additional data can be provided by AES finalization
                // => Base64 encode all we can, in order to have as much available space as possible for finalization

                // Check that total length is a multiple of 3 ; compute current remainder
                size_t cbBase64Remainder = m_cbAvailableForBase64 % 3;
                if (cbBase64Remainder != 0) {
                    
                    // Not the right length for base64
                    // => keep remainder bytes for next base64 encoding, only encode a number of bytes that is a multiple of 3
                    WLOG_FORMATED(LOGGER_TOKEN_BATCH, DEBUG_INT, "Writer/finalize: Data available for Base64 (=%lu) is not a multiple of 3 => keep %lu bytes of remainder", m_cbAvailableForBase64, cbBase64Remainder);
                }

                if (m_cbAvailableForBase64 > cbBase64Remainder) {

                    // Encode to Base64 the Base64 remainder of previous iteration + the ciphered block - the remainder of current iteration
                    cbBase64 = CBase64::EncodeBuffer (m_bufCipheredDataForBase64, m_cbAvailableForBase64-cbBase64Remainder, m_bufBase64output);
                    WLOG_FORMATED(LOGGER_TOKEN_BATCH, DEBUG_INT, "Writer/finalize: %d bytes of encrypted data encoded to %lu bytes of base 64 text", m_cbAvailableForBase64-cbBase64Remainder, cbBase64);

                    // write it to output file
                    m_cbWrittenBase64 += fwrite (m_bufBase64output, 1, cbBase64, m_pfTmpOutputFile);
                    WLOG_FORMATED(LOGGER_TOKEN_BATCH, DEBUG_INT, "Writer/finalize: %lu bytes of AES-256+Base64 written to output file - total ciphered data written : %llu", cbBase64, m_cbWrittenBase64);

                    // If there if a remainder for Base64
                    if (cbBase64Remainder != 0) {

                        // Copy it at the beginning of buffer in order to let ciphered data be copied after that remainder, so that it is base64-encoded after EAS finalization
                        WLOG_FORMATED(LOGGER_TOKEN_BATCH, DEBUG_INT, "Writer/finalize: Keep %lu bytes of remainder for next base 64 encoding", cbBase64Remainder);
                        for (unsigned int idxBase64Remainder=0; idxBase64Remainder<cbBase64Remainder; idxBase64Remainder++) {
                            m_bufCipheredDataForBase64[idxBase64Remainder] = m_bufCipheredDataForBase64[m_cbAvailableForBase64-cbBase64Remainder+idxBase64Remainder];
                        }
                    }   // end if there is a remainder for Base64 input

                    // At finalization we must know how many bytes of Base64 remainder are in buffer
                    m_cbAvailableForBase64 = cbBase64Remainder;

                }   // end if there are data to encode
            }   // end if there are data for Base64


            // Finalize encryption
            // If there is a remainder at beginning of buffer m_bufCipheredDataForBase64, copy ciphered data after it
            WLOG_FORMATED(LOGGER_TOKEN_BATCH, DEBUG_INT, "Writer: Finalize encryption ; there are %lu bytes of Base64 remainder from last iteration", m_cbAvailableForBase64);
            if (1 != EVP_EncryptFinal_ex (&m_evtCipherContext, m_bufCipheredDataForBase64+m_cbAvailableForBase64, &cbCiphered)) {
                ERR_load_crypto_strings();
                WLOG_FORMATED(LOGGER_TOKEN_BATCH, ERROR_INT, "AES encryption has failed to finalize :\n%s", ERR_error_string(ERR_get_error(), NULL));
                m_fEncryptError = true;
            }
            else {
                // Encode to Base64 the remainder and the last block
                // No matter if this is not a multiple of 3, it can add padding '=' chars as these are last bytes to encode
                m_cbAvailableForBase64 += cbCiphered;
                cbBase64 = CBase64::EncodeBuffer (m_bufCipheredDataForBase64, m_cbAvailableForBase64, m_bufBase64output);
                WLOG_FORMATED(LOGGER_TOKEN_BATCH, DEBUG_INT, "Writer/finalize: %lu bytes of (remainder + final encrypted data) encoded to %lu bytes of base 64 text", m_cbAvailableForBase64, cbBase64);

                // write it to output file
                m_cbWrittenBase64 += fwrite (m_bufBase64output, 1, cbBase64, m_pfTmpOutputFile);
                WLOG_FORMATED(LOGGER_TOKEN_BATCH, DEBUG_INT, "Writer/finalize: %lu last bytes of AES-256+Base64 written to output file - total ciphered data written : %llu", cbBase64, m_cbWrittenBase64);

                // All is valid => return number of bytes written
                retval = m_cbWrittenHeader+m_cbWrittenBase64;

            }   // End if encryption has succeeded to finalize
        }   // end if encryption of remainder data has succeeded
    }   // end if there were no errors during previous steps

    // Clean up AES context
    EVP_CIPHER_CTX_cleanup (&m_evtCipherContext);

    // Close temporary output file
    if (m_pfTmpOutputFile) {
        fclose (m_pfTmpOutputFile);
        m_pfTmpOutputFile = NULL;
    }

    // If operation has succeeded, move result file from temporary path to final requested path
    if (!m_fEncryptError) {
        WLOG_FORMATED(LOGGER_TOKEN_BATCH, DEBUG_INT, "Writer/finalize: Rename <%s> to <%s>", m_szTmpOutputFilePath, m_szOutputFilePath);
        FileUtils::RenameFile (m_szTmpOutputFilePath, m_szOutputFilePath);
    }
    else {
        // Error => remove temporary output file
        WLOG_FORMATED(LOGGER_TOKEN_BATCH, DEBUG_INT, "Writer/finalize: Encryption error => remove temporary file <%s>", m_szTmpOutputFilePath);
        ::remove (m_szTmpOutputFilePath);
    }

    // 0 if error, number of bytes written if success
    return retval;
}


