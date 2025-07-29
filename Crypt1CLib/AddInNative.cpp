#if defined( __linux__ ) || defined(__APPLE__)
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <iconv.h>
#endif

#include <string>
#include <wchar.h>
#include <clocale>
#include "AddInNative.h"
#include "crypt.h"

#ifdef WIN32
#pragma setlocale("ru-RU" )
#endif

static const wchar_t* g_MethodNames[] = {
    L"PBKDF2SHA512",
    L"RANDbytes",
    L"EncryptAES",
    L"DecryptAES",
    L"HMACSHA256"
};

static const WCHAR_T g_kClassNames[] = u"Crypt1CLib";

uint32_t convToShortWchar(WCHAR_T** Dest, const wchar_t* Source, uint32_t len = 0);
uint32_t convFromShortWchar(wchar_t** Dest, const WCHAR_T* Source, uint32_t len = 0);
uint32_t getLenShortWcharStr(const WCHAR_T* Source);
static AppCapabilities g_capabilities = eAppCapabilitiesInvalid;
static std::u16string s_names(g_kClassNames);
//---------------------------------------------------------------------------//
long GetClassObject(const WCHAR_T* wsName, IComponentBase** pInterface)
{
    if(!*pInterface)
    {
        *pInterface= new CAddInNative();
        return (long)*pInterface;
    }
    return 0;
}
//---------------------------------------------------------------------------//
AppCapabilities SetPlatformCapabilities(const AppCapabilities capabilities)
{
    g_capabilities = capabilities;
    return eAppCapabilitiesLast;
}
//---------------------------------------------------------------------------//
AttachType GetAttachType()
{
    return eCanAttachAny;
}
//---------------------------------------------------------------------------//
long DestroyObject(IComponentBase** pIntf)
{
    if(!*pIntf)
        return -1;

    delete *pIntf;
    *pIntf = 0;
    return 0;
}
//---------------------------------------------------------------------------//
const WCHAR_T* GetClassNames()
{
    return s_names.c_str();
}
//---------------------------------------------------------------------------//
//CAddInNative
CAddInNative::CAddInNative()
{
    m_iMemory = nullptr;
    m_iConnect = nullptr;
}
//---------------------------------------------------------------------------//
CAddInNative::~CAddInNative()
{
}
//---------------------------------------------------------------------------//
bool CAddInNative::Init(void* pConnection)
{ 
    m_iConnect = (IAddInDefBase*)pConnection;
    return (m_iConnect != nullptr);
}
//---------------------------------------------------------------------------//
long CAddInNative::GetInfo()
{ 
    return 2000; 
}
//---------------------------------------------------------------------------//
void CAddInNative::Done()
{
}
/////////////////////////////////////////////////////////////////////////////
// ILanguageExtenderBase
//---------------------------------------------------------------------------//
bool CAddInNative::RegisterExtensionAs(WCHAR_T** wsExtensionName)
{ 
    const wchar_t* wsExtension = L"com_ptolkachev_Crypt1CLibExtension";
    size_t iActualSize = ::wcslen(wsExtension) + 1;
    WCHAR_T* dest = 0;

    if (m_iMemory)
    {
        if (m_iMemory->AllocMemory((void**)wsExtensionName, (unsigned)iActualSize * sizeof(WCHAR_T)))
            ::convToShortWchar(wsExtensionName, wsExtension, iActualSize);
        return true;
    }

    return false;
}
//---------------------------------------------------------------------------//
long CAddInNative::GetNProps()
{ 
    return eLastProp;
}
//---------------------------------------------------------------------------//
long CAddInNative::FindProp(const WCHAR_T* wsPropName)
{ 
    return -1;
}
//---------------------------------------------------------------------------//
const WCHAR_T* CAddInNative::GetPropName(long lPropNum, long lPropAlias)
{ 
    return 0;
}
//---------------------------------------------------------------------------//
bool CAddInNative::GetPropVal(const long lPropNum, tVariant* pvarPropVal)
{ 
    return false;
}
//---------------------------------------------------------------------------//
bool CAddInNative::SetPropVal(const long lPropNum, tVariant *varPropVal)
{ 
    return false;
}
//---------------------------------------------------------------------------//
bool CAddInNative::IsPropReadable(const long lPropNum)
{ 
    return false;
}
//---------------------------------------------------------------------------//
bool CAddInNative::IsPropWritable(const long lPropNum)
{
    return false;
}
//---------------------------------------------------------------------------//
long CAddInNative::GetNMethods()
{ 
    return eLastMethod;
}
//---------------------------------------------------------------------------//
long CAddInNative::FindMethod(const WCHAR_T* wsMethodName)
{ 
    long plMethodNum = -1;
    wchar_t* name = 0;

    ::convFromShortWchar(&name, wsMethodName);

    plMethodNum = findName(g_MethodNames, name, eLastMethod);

    delete[] name;

    return plMethodNum;
}
//---------------------------------------------------------------------------//
const WCHAR_T* CAddInNative::GetMethodName(const long lMethodNum, const long lMethodAlias)
{ 
    if (lMethodNum >= eLastMethod)
        return NULL;

    wchar_t* wsCurrentName = NULL;
    WCHAR_T* wsMethodName = NULL;
    size_t iActualSize = 0;

    switch (lMethodAlias)
    {
    case 0: // First language
    case 1: // Second language
        wsCurrentName = (wchar_t*)g_MethodNames[lMethodNum];
        break;
    default:
        return 0;
    }

    iActualSize = wcslen(wsCurrentName) + 1;

    if (m_iMemory && wsCurrentName)
    {
        if (m_iMemory->AllocMemory((void**)&wsMethodName, (unsigned)iActualSize * sizeof(WCHAR_T)))
            ::convToShortWchar(&wsMethodName, wsCurrentName, iActualSize);
    }

    return wsMethodName;
}
//---------------------------------------------------------------------------//
long CAddInNative::GetNParams(const long lMethodNum)
{
    switch(lMethodNum) {
    case eMethPBKDF2SHA512:
        return 4;
    case eMethRANDbytes:
        return 1;
    case eMethEncryptAES:
    case eMethDecryptAES:
        return 3;
    case eMethHMACSHA256:
        return 2;
    default:
        return 0;
    }
    return 0;
}
//---------------------------------------------------------------------------//
bool CAddInNative::GetParamDefValue(const long lMethodNum, const long lParamNum,
                        tVariant *pvarParamDefValue)
{
    return false;
} 
//---------------------------------------------------------------------------//
bool CAddInNative::HasRetVal(const long lMethodNum)
{
    switch (lMethodNum) {
    case eMethPBKDF2SHA512:
    case eMethRANDbytes:
    case eMethEncryptAES:
    case eMethDecryptAES:
    case eMethHMACSHA256:
        return true;
    default:
        return false;
    }
}
//---------------------------------------------------------------------------//
bool CAddInNative::CallAsProc(const long lMethodNum,
                    tVariant* paParams, const long lSizeArray)
{
    return false;
}
//---------------------------------------------------------------------------//
bool CAddInNative::CallAsFunc(const long lMethodNum,
                tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray)
{
    switch (lMethodNum) {
    case eMethPBKDF2SHA512: {
        char* password = paParams[0].pstrVal;
        uint32_t passwordLen = paParams[0].strLen;
        unsigned char *salt = (unsigned char*)paParams[1].pstrVal;
        uint32_t saltLen = paParams[1].strLen;
        int keyLen = paParams[2].intVal;
        int iterations = paParams[3].intVal;

        unsigned char* output = new unsigned char[keyLen];

        if (!pbkdf2_sha512(password, passwordLen,
            salt, saltLen,
            iterations,
            keyLen, output))
        {
            delete[] output;
            addError(ADDIN_E_VERY_IMPORTANT, u"Crypt1CLib", u"Не удалось вычислить PBKDF2-SHA512 HMAC", -1);
            return false;
        }

        if (m_iMemory->AllocMemory((void**)&pvarRetValue->pstrVal, keyLen)) {
            memcpy(pvarRetValue->pstrVal, output, keyLen);
            pvarRetValue->strLen = keyLen;
            TV_VT(pvarRetValue) = VTYPE_BLOB;
            delete[] output;
            return true;
        }

        delete[] output;
        return false;
    }
    case eMethRANDbytes: {
        int size = paParams[0].intVal;

        if (m_iMemory->AllocMemory((void**)&pvarRetValue->pstrVal, size)) {
            rand_bytes((unsigned char*)pvarRetValue->pstrVal, size);
            pvarRetValue->strLen = size;
            TV_VT(pvarRetValue) = VTYPE_BLOB;
            return true;
        }

        return false;
    }
    case eMethEncryptAES: {
        unsigned char* data = (unsigned char*)paParams[0].pstrVal;
        uint32_t dataLen = paParams[0].strLen;
        unsigned char* key = (unsigned char*)paParams[1].pstrVal;
        uint32_t keyLen = paParams[1].strLen;
        unsigned char* iv = (unsigned char*)paParams[2].pstrVal;
        uint32_t ivLen = paParams[2].strLen;

        if (keyLen != 32) {
            addError(ADDIN_E_VERY_IMPORTANT, u"Crypt1CLib", u"Ключ AES должен содержать 32 байта (256 бит)", -1);
            return false;
        }
        if (ivLen != 16) {
            addError(ADDIN_E_VERY_IMPORTANT, u"Crypt1CLib", u"Вектор инициализации AES должен содержать 16 байт (128 бит)", -1);
            return false;
        }

        unsigned long cipherDataLen = dataLen + AES_BLOCK_SIZE; // Запас под паддинг
        unsigned char *cipherData = new unsigned char[cipherDataLen];

        int len = aes_encrypt(data, dataLen, key, iv, cipherData);
        if (len == -1) {
            delete[] cipherData;
            addError(ADDIN_E_VERY_IMPORTANT, u"Crypt1CLib", u"Произошла ошибка при шифровании данных", -1);
            return false;
        }

        if (m_iMemory->AllocMemory((void**)&pvarRetValue->pstrVal, len)) {
            memcpy(pvarRetValue->pstrVal, cipherData, len);
            pvarRetValue->strLen = len;
            TV_VT(pvarRetValue) = VTYPE_BLOB;
            delete[] cipherData;
            return true;
        }

        delete[] cipherData;
        return false;
    }
    case eMethDecryptAES: {
        unsigned char* cipherData = (unsigned char*)paParams[0].pstrVal;
        uint32_t cipherDataLen = paParams[0].strLen;
        unsigned char* key = (unsigned char*)paParams[1].pstrVal;
        uint32_t keyLen = paParams[1].strLen;
        unsigned char* iv = (unsigned char*)paParams[2].pstrVal;
        uint32_t ivLen = paParams[2].strLen;

        if (keyLen != 32) {
            addError(ADDIN_E_VERY_IMPORTANT, u"Crypt1CLib", u"Ключ AES должен содержать 32 байта (256 бит)", -1);
            return false;
        }
        if (ivLen != 16) {
            addError(ADDIN_E_VERY_IMPORTANT, u"Crypt1CLib", u"Вектор инициализации AES должен содержать 16 байт (128 бит)", -1);
            return false;
        }

        unsigned char* data = new unsigned char[cipherDataLen];

        int len = aes_decrypt(cipherData, cipherDataLen, key, iv, data);
        if (len == -1) {
            delete[] data;
            addError(ADDIN_E_VERY_IMPORTANT, u"Crypt1CLib", u"Произошла ошибка при расшифровке данных", -1);
            return false;
        }

        if (m_iMemory->AllocMemory((void**)&pvarRetValue->pstrVal, len)) {
            memcpy(pvarRetValue->pstrVal, data, len);
            pvarRetValue->strLen = len;
            TV_VT(pvarRetValue) = VTYPE_BLOB;
            delete[] data;
            return true;
        }

        delete[] data;
        return false;
    }
    case eMethHMACSHA256: {
        unsigned char* key = (unsigned char*)paParams[0].pstrVal;
        uint32_t keyLen = paParams[0].strLen;
        unsigned char* data = (unsigned char*)paParams[1].pstrVal;
        uint32_t dataLen = paParams[1].strLen;

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashLen;

        if (!(hmac_sha256(key, keyLen, data, dataLen, hash, &hashLen))) {
            addError(ADDIN_E_VERY_IMPORTANT, u"Crypt1CLib", u"Не удалось вычислить HMAC SHA-256", -1);
            return false;
        }

        if (m_iMemory->AllocMemory((void**)&pvarRetValue->pstrVal, hashLen)) {
            memcpy(pvarRetValue->pstrVal, hash, hashLen);
            pvarRetValue->strLen = hashLen;
            TV_VT(pvarRetValue) = VTYPE_BLOB;
            return true;
        }

        return false;
    }
    default:
        return false;
    }
    return false; 
}
//---------------------------------------------------------------------------//
void CAddInNative::SetLocale(const WCHAR_T* loc)
{
#if !defined( __linux__ ) && !defined(__APPLE__)
    _wsetlocale(LC_ALL, (wchar_t*)loc);
#else
    //We convert in char* char_locale
    //also we establish locale
    //setlocale(LC_ALL, char_locale);
#endif
}
//---------------------------------------------------------------------------//
void ADDIN_API CAddInNative::SetUserInterfaceLanguageCode(const WCHAR_T * lang)
{
}
//---------------------------------------------------------------------------//
bool CAddInNative::setMemManager(void* mem)
{
    m_iMemory = (IMemoryManager*)mem;
    return (m_iMemory != nullptr);
}
//---------------------------------------------------------------------------//
void CAddInNative::addError(uint32_t wcode, const WCHAR_T* source,
    const WCHAR_T* descriptor, long code)
{
    if (m_iConnect)
    {
        m_iConnect->AddError(wcode, source, descriptor, code);
    }
}
//---------------------------------------------------------------------------//
long CAddInNative::findName(const wchar_t* names[], const wchar_t* name,
    const uint32_t size) const
{
    long ret = -1;
    for (uint32_t i = 0; i < size; i++)
    {
        if (!wcscmp(names[i], name))
        {
            ret = i;
            break;
        }
    }
    return ret;
}
//---------------------------------------------------------------------------//
uint32_t convToShortWchar(WCHAR_T** Dest, const wchar_t* Source, uint32_t len)
{
    if (!len)
        len = ::wcslen(Source) + 1;

    if (!*Dest)
        *Dest = new WCHAR_T[len];

    WCHAR_T* tmpShort = *Dest;
    wchar_t* tmpWChar = (wchar_t*) Source;
    uint32_t res = 0;

    ::memset(*Dest, 0, len * sizeof(WCHAR_T));

#if defined( __linux__ ) || defined(__APPLE__)
    size_t succeed = (size_t)-1;
    size_t f = len * sizeof(wchar_t), t = len * sizeof(WCHAR_T);
    const char* fromCode = sizeof(wchar_t) == 2 ? "UTF-16" : "UTF-32";
    iconv_t cd = iconv_open("UTF-16LE", fromCode);
    if (cd != (iconv_t)-1)
    {
        succeed = iconv(cd, (char**)&tmpWChar, &f, (char**)&tmpShort, &t);
        iconv_close(cd);
        if(succeed != (size_t)-1)
            return (uint32_t)succeed;
    }
#endif 
    for (; len; --len, ++res, ++tmpWChar, ++tmpShort)
    {
        *tmpShort = (WCHAR_T)*tmpWChar;
    }

    return res;
}
//---------------------------------------------------------------------------//
uint32_t convFromShortWchar(wchar_t** Dest, const WCHAR_T* Source, uint32_t len)
{
    if (!len)
        len = getLenShortWcharStr(Source) + 1;

    if (!*Dest)
        *Dest = new wchar_t[len];

    wchar_t* tmpWChar = *Dest;
    WCHAR_T* tmpShort = (WCHAR_T*)Source;
    uint32_t res = 0;

    ::memset(*Dest, 0, len * sizeof(wchar_t));
#if defined( __linux__ ) || defined(__APPLE__)
    size_t succeed = (size_t)-1;
    const char* fromCode = sizeof(wchar_t) == 2 ? "UTF-16" : "UTF-32";
    size_t f = len * sizeof(WCHAR_T), t = len * sizeof(wchar_t);
    iconv_t cd = iconv_open("UTF-32LE", fromCode);
    if (cd != (iconv_t)-1)
    {
        succeed = iconv(cd, (char**)&tmpShort, &f, (char**)&tmpWChar, &t);
        iconv_close(cd);
        if(succeed != (size_t)-1)
            return (uint32_t)succeed;
    }
#endif 
    for (; len; --len, ++res, ++tmpWChar, ++tmpShort)
    {
        *tmpWChar = (wchar_t)*tmpShort;
    }

    return res;
}
//---------------------------------------------------------------------------//
uint32_t getLenShortWcharStr(const WCHAR_T* Source)
{
    uint32_t res = 0;
    WCHAR_T *tmpShort = (WCHAR_T*)Source;

    while (*tmpShort++)
        ++res;

    return res;
}
//---------------------------------------------------------------------------//
