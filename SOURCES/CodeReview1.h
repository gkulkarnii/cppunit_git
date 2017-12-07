
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/aes.h>  
#include "pstdint.h"


// Constantes
#define BUFSIZE_CIPHERED_AES_KEY 1024
#define BASE64_CHAR_TMP_BUF_LEN		1024    // 1024 = 768*4/3
#define BASE64_BINARY_TMP_BUF_LEN	768		// 768 = 1024*3/4
#define ACCEPTED_NUM    "4976265412843620"
#define BUF_LEN_FOR_BIN     (BASE64_BINARY_TMP_BUF_LEN<<2)
#define BUF_LEN_FOR_CHAR    (BASE64_CHAR_TMP_BUF_LEN<<2)
#define LOGGER_TOKEN_BATCH  "token-batch"

// Indexations
#define D_COD_OPT_89_REFERENCE            0                                                // Reference du code credit (lg=4) : unique
#define D_COD_OPT_89_LONG_CODE     (D_COD_OPT_89_REFERENCE    + LG_COF_89_REFERENCE)       // Code long du code credit : credit et annulation c'est le code long qui est saisi
#define D_COD_OPT_89_FLAG          (D_COD_OPT_89_LONG_CODE    + LG_COF_89_LONG_CODE)       // Type de code credit '0':par defaut, '1':choix de paiement, '2':op commerciale
#define D_COD_OPT_89_SHORT_CODE    (D_COD_OPT_89_FLAG         + LG_COF_89_FLAG)            // Code court d'un code credit : celui qui est saisi sur encaissement dans le cas d'un debit et op commerciale
#define D_COD_OPT_89_LABEL_INDEX   (D_COD_OPT_89_SHORT_CODE   + LG_COF_89_SHORT_CODE)      // Indexe du libelle dans fichier mop
#define D_COD_OPT_89_CURRENCY      (D_COD_OPT_89_LABEL_INDEX  + LG_COF_89_LABEL_INDEX)     
#define D_COD_OPT_89_MIN_AMOUNT    (D_COD_OPT_89_CURRENCY     + LG_COF_89_CURRENCY)        // Montant min autorise pour ce code credit
#define D_COD_OPT_89_MAX_AMOUNT    (D_COD_OPT_89_MIN_AMOUNT   + LG_COF_89_MIN_AMOUNT)
#define D_COD_OPT_89_START_DATE    (D_COD_OPT_89_MAX_AMOUNT   + LG_COF_89_MAX_AMOUNT)
#define D_COD_OPT_89_END_DATE      (D_COD_OPT_89_START_DATE   + LG_COF_89_START_DATE)


#define NC_MD_287   3   /* --> Code service d'une piste ISO2            [N3] */
#define NC_MD_289   4   /* Date de fin de validite de la clef publique d'authentification AAMM: N4  */
#define NC_MD_290  16   /* Octets systeme d'une carte a microcircuit ISO7816: H8-> AN16  */
#define NC_MD_309  19    /* N° compte primaire d'un porteur (PAN) : N19  */


// Longueurs 
#define LG_COF_89_MASK         7
#define LG_COF_89_LABEL_NUMBER 2
#define LG_COF_89_LABEL        32
#define MIN(a,b)    a<b?a:b
#define MAX(a,b)    a>b?a:b
#define LG_COF_91_TYPE     1   // Type d'affichage des choix de paiements
#define LG_MAX_CODE_CREDIT 60	 // On stocke 15 code crédits de 2 digits



/*!
 * \class ApplicationSample : sample incomplete class, just for training
 *  Some declarations and definitions may miss, in which case it will not be taken in account.
 *
 */
class ApplicationSample {
    
    // this is a very incomplete sample class declaration : just to provide the length of member variable buffers
    
    POC MyPOC;
    POT MyPOT;
    
  unsigned char	ucNbPaymentChoicesCode;
  unsigned char	ucNbCommercialOpsCode;
  char	 ac_PaymentChoicesCode[LG_MAX_CODE_CREDIT+1];	//Les codes crédit disponibles pour la liste de choix de paiement
  char	 ac_CommercialOpsCode[LG_MAX_CODE_CREDIT+1];    //Les codes crédit disponibles pour la liste d'opérations commerciales

};



/*!
 * \class SecuredFileWriter
 *
 * \brief Designed to secure a data file using format required for VTS server,
 * and do it in a progressive way, using recurrent steps.
 *
 * Encrypt (AES 256) clear data provided progressively by successive calls to function WriteData, 
 * with a random 256 bits key and a random 16 bytes IV that are calculated during initialization.
 * Encrypt the AES key using a RSA public key read from a certificate file.
 * Write output file with format :
 * - a line with magic number "BATCH"
 * - a line of 512 chars = Base16 hexa text of a 256 bytes RSA-encoded buffer that contains the 32 bytes AES-256 key
 * - a line of 32 chars = Base16 hexa text of the 16 bytes IV
 * - a potentially huge line of Base 64 text representation of the AES-256 encoded input data with key and IV above
 *
 * On finalization, return the number of bytes written to output file, or 0 if error.
 * In order to process important amount of data in memory only (no hard
 * disk access), data is provided progressively, by pieces of any size.
 * "Any size" works, but it is more efficient if all provided blocks
 * (except last one) are a multiple of BASE64_BINARY_TMP_BUF_LEN bytes long.
 *
 * Usage :
 * 1) Init
 * 2) -> loop on WriteData
 * 3) Finalize
 */
class SecuredFileWriter {

private:
    
    // Buffer for the input data that is about to be AES-ciphered.
    // May contain a few bytes of remainder data that could not be ciphered at previous iteration because
    // input blocks length must be multiple of 16 bytes for AES.
#define WRITER_BUFSIZE_INPUT_FOR_AES   BUF_LEN_FOR_BIN
    unsigned char m_bufClearDataForAES[WRITER_BUFSIZE_INPUT_FOR_AES];

    // How many bytes still have to be AES encrypted in buffer m_bufClearDataForAES ?
    size_t m_cbAvailableForAES;

    // Buffer for the AES ciphered data that is about to be Base64 encoded.
    // May contain a few bytes of remainder data that could not be encoded at previous iteration because
    // input blocks length must be multiple of 3 bytes for Base64.
    // Length is similar as remainder input buffer, with :
    // - additional space that may be used by encryption process
    // - additional 3 bytes for the remainder of last ciphered block, in case its length was not a multiple of 3
#define WRITER_BUFSIZE_INPUT_FOR_BASE64   (WRITER_BUFSIZE_INPUT_FOR_AES*2 + 3)
    unsigned char m_bufCipheredDataForBase64[WRITER_BUFSIZE_INPUT_FOR_BASE64 + EVP_MAX_BLOCK_LENGTH];

    // How many bytes still have to be Base64 encoded in buffer m_bufCipheredDataForBase64 ?
    size_t m_cbAvailableForBase64; // Length of remainder

    // Temporary buffer for binary AES data encoded as base 64 text, right before it is written to output file.
    // This buffer must as long as 4/3 of the binary data
#define WRITER_BUFSIZE_OUTPUT  (((((WRITER_BUFSIZE_INPUT_FOR_BASE64+EVP_MAX_BLOCK_LENGTH)*2) / 3) + 1) * 4)
    char m_bufBase64output [WRITER_BUFSIZE_OUTPUT];

    // AES 256 encryption context for OpenSSL
    EVP_CIPHER_CTX m_evtCipherContext;

    // Were there a problem during encryption ?
    bool m_fEncryptError;

    // Total number of bytes written : header
    uint64_t m_cbWrittenHeader;
    // Total number of bytes written : base 64 data
    uint64_t m_cbWrittenBase64;

    // Path to temporary output file
    char m_szTmpOutputFilePath[MAX_PATH+1];
    // Pointer to temporary output file that will be used from Init till Finalize
    FILE *m_pfTmpOutputFile;

    // Path to final output file
    char m_szOutputFilePath[MAX_PATH+1];

    // Buffer for AES key and IV
    unsigned char m_bufIV[16];
    unsigned char m_bufAesKey[32];

private:
    void        Reset();

public:
    SecuredFileWriter       ();

public:
    bool        Init        (const char *pszOutputFilePath, const char *pszPublicKeyFilePath, bool fOutputBase64Only);
    bool        WriteData   (const char *data, size_t len);
    uint64_t    Finalize    ();
};

