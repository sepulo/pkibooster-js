/**
 * Copyright (C) 2014 Mehdi Bahrbegi (m.bahribayli@gmail.com)
 * <p/>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 * <p/>
 */


/*
 #############################################################################
 #                                Helper Functions                           #
 #############################################################################
 */

// Is PKI Booster loaded
var _pbLoaded = false;

// PKI Booster callback function
var _pbCallback = null;

// A reference to PKI Booster applet
var _pkiBoosterApplet = null;

// Applet code base
var _appletCodeBase = ".";
var _appletArchive = "pkibooster.jar";
var _acitveXCodeBase = "pkiactivex.dll";

// ActiveX code base
var _activexCodeBase;

/**
 * Loads PKI Booster with preferred flavor
 *
 * @param {Number?} preferredFlavor Available flavors are @link{PB_FLAVOR_APPLET}
 *  and @link{PB_FLAVOR_ACTIVEX}.
 *
 * @param {Function} pbCallback a callback function that is called when PKI Booster is
 * loaded and ready to use.
 *
 * @throws Error if PKI Booster already loaded.
 */
function loadPKIBooster(preferredFlavor, pbCallback) {
    if(_pbLoaded)
        throw new Error("PKI Booster already loaded", PB_ERROR_PKI_BOOSTER_ALREADY_LOADED);
    if(!preferredFlavor)
        preferredFlavor = PB_FLAVOR_DEFAULT;
    _pbCallback = pbCallback;
    pkiBooster = new _PKIBoosterManager(preferredFlavor);
    _pbLoaded = true;
    if(pkiBooster._pkiBoosterReady)
        _pbCallback();
}

/**
 * A callback function that is fired when PKI Booster applet is ready.
 * It is called from applet's i nit() method.
 */
function onPKIBoosterAppletReady() {
    // alert("onPKIBoosterAppletReady()");
     _pkiBoosterApplet = document.getElementsByName("pkiBoosterApplet")[0];
     pkiBooster.pbObjFactory = _pkiBoosterApplet.getObjectFactory();
     pkiBooster._pkiBoosterReady = true;
     _pbCallback();
}

/**
 *
 * @type {Boolean}
 */

// Whether deployJava script from Oracle loaded
var isDeployJavaLoaded = false;

/**
 * Dynamically loads a Javascript file
 * @param url the URL of the script to be loaded
 * @param callback a callback function to call when script loaded
 */
function loadJavascript(url, callback) {
    var head = document.getElementsByTagName('head')[0];
    var script = document.createElement('script');
    script.type = 'text/javascript';
    script.src = url;

    script.onreadystatechange = callback;
    script.onload = callback;

    // Load script
    head.appendChild(script);
}

/**
 * A callback function called when deployJava script loaded.
 * It sets isDeployJavaLoaded to true.
 */
function deployJavaLoaded() {
    isDeployJavaLoaded = true;
}


// Load deployJava script from Oracle
loadJavascript("https://www.java.com/js/deployJava.js", deployJavaLoaded);


/*
 Internet Explorer Browser detector v0.5.1
 By Eric Gerds   http://www.pinlady.net/PluginDetect/
 */

/**
 * Checks whether code is loaded in Internet Explorer browser.
 * @return {Boolean} returns true if the browser is Internet Explorer
 * returns false otherwise  .
 */

function isInternetExplorer() {
    var tmp = document.documentMode, e;
    // Try to force this property to be a string.
    try{document.documentMode = "";}
    catch(e){ }

    // If document.documentMode is a number, then it is a read-only property, and so
    // we have IE 8+.
    // Otherwise, if conditional compilation works, then we have IE < 11.
    // Otherwise, we have a non-IE browser.
    var isIE = typeof document.documentMode == "number" || eval("/*@cc_on!@*/!1");

    // Switch back the value to be unobtrusive for non-IE browsers.
    try{document.documentMode = tmp;}
    catch(e){ }
    return isIE;
}


/**
 * Checks whether appropriate Java Runtime Environment version is
 * installed and available in browser.
 *
 * @return {Boolean} returns true if Java Runtime Environment is installed
 * returns false otherwise.
 */

function isJREInstalled() {
    return true;//javaDeploy.versionCheck('1.6.0_10+');
}


/**
 * Checks whether PKI Booster COM library is installed.
 *
 * @return {Boolean} returns true if PKI Booster COM library is installed on
 * computer returns false otherwise.
 */
function isActiveXInstalled() {
    var obj = null;
    try {
        obj =  new ActiveXObject("pkiactivex.Util");
    }
    catch (ex) {
        obj = null;
    }
    return obj != null;
}

// CRLF helper string
var CRLF = "\u000a\u000d";

/*
 #############################################################################
 #                                Constants                                  #
 #############################################################################
 */

// Error Codes
var PB_ERROR_FLAVOR_ALREADY_SET          = 0x200001;
var PB_ERROR_ONLY_INTERNET_EXPLORER      = 0x200002;
var PB_ERROR_JRE_IS_NOT_INSTALLED        = 0x200003;
var PB_ERROR_PKI_BOOSTER_ALREADY_LOADED  = 0x200004;

// User Types
var PB_UT_SO   = 0;
var PB_UT_USER = 1;

// Flavors
var PB_FLAVOR_DEFAULT  = 0;
var PB_FLAVOR_APPLET   = 1;
var PB_FLAVOR_ACTIVEX  = 2;

// Symmetric Encryption Algorithms
var ALGORITHM_RC4             = 73;
var ALGORITHM_DES             = 74;
var ALGORITHM_3DES            = 75;
var ALGORITHM_RC2             = 76;
var ALGORITHM_AES128          = 77;
var ALGORITHM_AES192          = 78;
var ALGORITHM_AES256          = 79;
var ALGORITHM_BLOWFISH        = 88;
var ALGORITHM_CAST128         = 91;
var ALGORITHM_IDEA            = 92;
var ALGORITHM_SEED            = 104;
var ALGORITHM_RABBIT          = 105;

// Hash Algorithms
var ALGORITHM_SHA1            = 29;
var ALGORITHM_MD5             = 30;
var ALGORITHM_MD2             = 31;
var ALGORITHM_SHA256          = 32;
var ALGORITHM_SHA384          = 33;
var ALGORITHM_SHA512          = 34;
var ALGORITHM_SHA224          = 35;
var ALGORITHM_MD4             = 36;
var ALGORITHM_RIPEMD160       = 37;
var ALGORITHM_CRC32           = 38;
var ALGORITHM_SSL3            = 39;
var ALGORITHM_GOST_R3411_1994 = 40;
var ALGORITHM_LAST            = 41;




/*
 #############################################################################
 #                                Helper Classes                             #
 #############################################################################
 */


/**
 * Reference to singleton instance of @link{_PKIBoosterManager}
 *
 */

var pkiBooster = null;

/**
 * A singleton class that manages usage of PKIBooster in the browser. It allows
 * the user to select the the flavor, ActiveX or Applet, he prefers. The Browsers
 * should support the flavor that user selects.
 *
 * @param flavor {Number} selects preferred flavor. Available flavors are @link{PB_FLAVOR_APPLET}
 *  and @link{PB_FLAVOR_ACTIVEX}. Special flavor @link{PB_FLAVOR_DEFAULT} automatically sets best
 *  flavor for the browser at hand.
 *
 * @private
 */

function  _PKIBoosterManager(preferedFalvor) {
    /**
     * It keeps the result of @link{isInternetExplorer()} to prevent calling it
     * over and over
     * @type {Boolean}
     */
    var internetExplorer = isInternetExplorer();

    /**
     * It keeps the result of @link{isJREInstalled()} to prevent calling it
     * over and over
     * @type {Boolean}
     */
    var jreInstalled = isJREInstalled();

    /**
     * Specifies the flavor chosen by user. If user
     * does not specify the flavor it is automatically set by
     * script.
     * @type {String}
     */
    this.flavor = "";

    /**
     * Reference to CryptoObjectFactory object
     */
    this.pbObjFactory = null;

    /**
     * Specifies whether PKI Booster is loaded and ready to use.
     *
     * @type {Boolean}
     */
    this._pkiBoosterReady = true;

    /**
     * Selects ActiveX flavor if flavor is not already set by user.
     *
     * @throws Error if browser at hand is nto Internet Explorer.
     */

    this._useActiveX = function() {
        if(!internetExplorer)
            throw new Error("ActiveX is only available in Internet Explorer.", PB_ERROR_ONLY_INTERNET_EXPLORER);
        this.flavor = "activex";
    }

    /**
     * Selects Applet flavor if flavor is not already set by user.
     *
     * @throws Error if Java Runtime Environment is not installed or not available
     * in the browser in hand.
     */
    this._useApplet = function() {
        if(!jreInstalled)
            throw new Error("Java Runtime Environment is not installed so Applet is not available.", PB_ERROR_JRE_IS_NOT_INSTALLED);
        this.flavor = "applet";
    }

    /**
     * Sets appropriate default flavor and complains if none is possible.
     * It also creates an instance of PKIBoosterApplet if Applet flavor is used.
     */
    {
        switch(preferedFalvor) {
            case PB_FLAVOR_ACTIVEX:
                this._useActiveX();
                break;
            case PB_FLAVOR_APPLET:
                this._useApplet();
                break;
            default:
                //default flavor for Internet Explorer is ActiveX
                if(internetExplorer)
                    this._useActiveX();

                else {
                    if(!jreInstalled) {
                        alert("PKI Booster:" + CRLF +
                            "Java Runtime Environment is not available in this browser." + CRLF +
                            "Install Java Runtime Environment or use Internet Explorer to load ActiveX flavor.");
                        throw new Error("Java Runtime Environment is not available in this browser.", PB_ERROR_JRE_IS_NOT_INSTALLED);
                    }
                    this._useApplet();
                }
        }

        if(this.flavor == "applet") {
            this._pkiBoosterReady = false;
            var body = document.getElementsByTagName('body')[0];

            if(!document.getElementsByName(("pkiBoosterApplet"))[0]) {
               var pbApplet = document.createElement("applet");
                pbApplet.name = "pkiBoosterApplet";
                pbApplet.codeBase =_appletCodeBase;
                pbApplet.archive = _appletArchive;
                pbApplet.code = "com.vancosys.pki.applet.PKIApplet";
                pbApplet.style.width = '0';
                pbApplet.style.height = '0';
				
                // Load Applet
                body.appendChild(pbApplet);
            }


        }
        //check if ActiveX is installed and install it if it is not already installed.
        else if(this.flavor == "activex") {
            this._pkiBoosterReady = isActiveXInstalled();
            if(!this._pkiBoosterReady) {
                var body = document.getElementsByTagName('body')[0];

                if(!document.getElementsByName(("pkiBoosterUtil"))[0]) {
                    var pbUtil = document.createElement("object");
                    pbUtil.name = "pkiBoosterUtil";
                    pbUtil.classid = "clsid:2F8EA280-ABE5-4A70-81C0-CDEC448FA0D1";
                    pbUtil.codeBase =_acitveXCodeBase;
                    pbUtil.clientHeight = 0;
                    pbUtil.clientWidth = 0;
                    pbUtil.style = "height: 0; width: 0";
                    // Install ActiveX
                    body.appendChild(pbUtil);
                }
                throw new Error("<pre>You are going to use PKI Booster on your Internet Explorer " + CRLF +
								" for first time. Be patient for a couple of " + CRLF +
								"minutes while PKI Booster is preparing. Then reload this page again." + CRLF + 
								"This will occur only once.</pre>");
            }
        }
    }
}




/*
 #############################################################################
 #                                Wrapper Classes                            #
 #############################################################################
 */



/********************************* PKCS11Storage *****************************/

/**
 * A wrapper class around PKCS11Storage
 * @constructor
 */


function PKCS11Storage () {

    //Wrapped certificate storage object.
    this._innerStorage = null;

    // CryptoProvider
    this._cryptoProvider = null;

    // Keeps flavor
    var applet = (pkiBooster.flavor == "applet");

    {
        if(applet)
            this._innerStorage = pkiBooster.pbObjFactory.createPKCS11Storage();
        else
            this._innerStorage = new ActiveXObject("pkiactivex.PKCS11Storage");
    }

    /**
     * Sets Dll file name for PKCS#11 interface
     * @param {String} dllName PKCS#11 interface file path
     */
    this.setDllName = function(dllName) {
        if(applet)
            this._innerStorage.setDllName(dllName);
        else
            this._innerStorage.DllName = dllName;
    }

    /**
     * Opens PKCS11Storage
     */
    this.open = function() {
        if(applet)
            this._innerStorage.open();
        else
            this._innerStorage.Open();
    }

    /**
     * Opens a session to PKCS#11 storage and returns a @link{_PKCS11SessionInfo} object.
     *
     * @param {Number} slot an integer number that specifies slot number on PKCS#11 storage
     * @param {Boolean} readonly specifies whether storage will be opened readonly
     * @return {_PKCS11SessionInfo} session info for open session
     */

    this.openSession = function (slot, readonly) {
        var innerSessionInfo = null;
        if(applet)
            innerSessionInfo = this._innerStorage.openSession(slot, readonly);
        else
            innerSessionInfo = this._innerStorage.OpenSession(slot, readonly);
        var sessionInfo = new _PKCS11SessionInfo();
        sessionInfo._innerSessionInfo = innerSessionInfo;

        this._cryptoProvider = new _CryptoProvider();
        if(applet)
            this._cryptoProvider._innerCryptoProvider = this._innerStorage.getCryptoProvider();
        else
            this._cryptoProvider._innerCryptoProvider = this._innerStorage.CryptoProvider;

        return sessionInfo;
    }

    /**
     * Closes PKCS#11 storage.
     */
    this.close = function() {
        if(applet)
            this._innerStorage.close();
        else
            this._innerStorage.Close();

    }

    /**
     * Returns cryptographic service provider for this PKCS#11 device
     * @return {_CryptoProvider}
     */
    this.getCryptoProvider = function() {
        return this._cryptoProvider;
    }

    /**
     * Returns number of certificates in the storage
     * @return {Number} number of certificates
     */
    this.getCount = function () {
        if(applet)
            return this._innerStorage.getCount();
        else
            return this._innerStorage.Count;
    }

    /**
     *  Returns the certificate object at index.
     *
     * @param {Number} index the index of required certificate
     * @return {_Certificate}
     */
    this.getCertificate = function(index) {
        var innerCert = null;
        //todo: first lookup the cert in the internal map
        if(applet)
            innerCert = this._innerStorage.getCertificate(index);
        else
            innerCert = this._innerStorage.GetCertificate(index);

        var cert = new _Certificate();
        cert._innerCertificate = innerCert;
        cert._loadInternals();

        return cert;
    }

    /**
     * Returns PKCS#11 storage open status
     * @return {Boolean} returns true if storage is open and returns false otherwise
     */
    this.isOpened = function () {
        if(applet)
            return this._innerStorage.isOpened();
        else
            return this._innerStorage.Opened;
    }

    /**
     *  Returns the certificate object by certificate thumbprint(SHA-1 hash).
     *
     * @param thumbprint {String} Certificate SHA-1 hash(thumbprint)
     * @return {_Certificate}
     */
    this.findByHash = function(thumbprint) {
        var innerCert = null;
        //todo: first lookup the cert in the internal map
        if(applet)
            innerCert = this._innerStorage.findByHash(thumbprint);
        else
            innerCert = this._innerStorage.FindByHash(thumbprint);

        var cert = new _Certificate();
        cert._innerCertificate = innerCert;
        cert._loadInternals();

        return cert;
    }
}

/********************************* PKCS11SessionInfo *************************/

/**
 * A wrapper class around PKCS11SessionInfo. The class is a private class and
 * is only create by @link{PKCS11Storage.openSession}
 * @private
 */
function _PKCS11SessionInfo() {
    //Keeps flavor
    var applet = (pkiBooster.flavor == "applet");

    //Wrapped session info object
    this._innerSessionInfo = null;

    /**
     * Logs in as user or SO in current session
     * @param {Number} userType An integer number that specifies PKCS#11 user type. 1. User 0. Security Officer
     * @param {String} password Password or PIN for the user
     */
    this.login = function(userType, password) {
        if(applet)
            this._innerSessionInfo.login(userType, password);
        else
            this._innerSessionInfo.Login(userType, password);
    }

    /**
     * Logs out from on this session
     */
    this.logout = function() {
        if(applet)
            this._innerSessionInfo.logout();
        else
            this._innerSessionInfo.Logout();

    }

}
/********************************* WinStorage ********************************/

/**
 * A wrapper class around WinStorage class
 * WinStorage represents Windows Certificate Storage
 *
 * @constructor
 */
function WinStorage() {
    //Keeps flavor
    var applet = (pkiBooster.flavor == "applet");

    //Wrapped WinStorage object
    this._innerStorage = null;

    {
        if(applet)
            this._innerStorage = pkiBooster.pbObjFactory.createWinStorage();
        else
            this._innerStorage = new ActiveXObject("pkiactivex.WinStorage");
    }

    /**
     * Returns number of certificates in the storage
     * @return {Number} number of certificates
     */
    this.getCount = function () {
        if(applet)
            return this._innerStorage.getCount();
        else
            return this._innerStorage.Count;
    }

    /**
     *  Returns the certificate object at index.
     *
     * @param {Number} index the index of required certificate
     * @return {_Certificate}
     */
    this.getCertificate = function(index) {
        var innerCert = null;
        //todo: first lookup the cert in the internal map
        if(applet)
            innerCert = this._innerStorage.getCertificate(index);
        else
            innerCert = this._innerStorage.GetCertificate(index);

        var cert = new _Certificate();
        cert._innerCertificate = innerCert;
        cert._loadInternals();

        return cert;
    }

    /**
     *  Returns the certificate object by certificate thumbprint(SHA-1 hash).
     *
     * @param thumbprint {String} Certificate SHA-1 hash(thumbprint)
     * @return {_Certificate}
     */
    this.findByHash = function(thumbprint) {
        var innerCert = null;
        //todo: first lookup the cert in the internal map
        if(applet)
            innerCert = this._innerStorage.findByHash(thumbprint);
        else
            innerCert = this._innerStorage.FindByHash(thumbprint);

        var cert = new _Certificate();
        cert._innerCertificate = innerCert;
        cert._loadInternals();

        return cert;
    }
}
/********************************* MemoryStorage *****************************/

/**
 * A wrapper class around MemoryStorage class
 *
 * @constructor
 */
function MemoryStorage() {
    //Keeps flavor
    var applet = (pkiBooster.flavor == "applet");

    //Wrapped MemoryStorage object
    this._innerStorage = null;

    {
        if(applet)
            this._innerStorage = pkiBooster.pbObjFactory.createMemoryStorage();
        else
            this._innerStorage = new ActiveXObject("pkiactivex.MemoryStorage");
    }

    /**
     * Returns number of certificates in the storage
     * @return {Number} number of certificates
     */
    this.getCount = function () {
        if(applet)
            return this._innerStorage.getCount();
        else
            return this._innerStorage.Count;
    }

    /**
     *  Returns the certificate object at index.
     *
     * @param {Number} index the index of required certificate
     * @return {_Certificate}
     */
    this.getCertificate = function(index) {
        var innerCert = null;
        //todo: first lookup the cert in the internal map
        if(applet)
            innerCert = this._innerStorage.getCertificate(index);
        else
            innerCert = this._innerStorage.GetCertificate(index);

        var cert = new _Certificate();
        cert._innerCertificate = innerCert;
        cert._loadInternals();

        return cert;
    }

    /**
     * Adds the certificate to this storage.
     *
     * @param {_Certificate} cert the certificate to be added
     * @param {Boolean} copyPrivateKey specifies whether private key will be added.
     */
    this.add = function(cert, copyPrivateKey) {
        var innerCert = cert._innerCertificate;

        if(applet)
            innerCert = this._innerStorage.add(innerCert, copyPrivateKey);
        else
            innerCert = this._innerStorage.Add(innerCert, copyPrivateKey);
    }
    /**
     * Clears all certificates in memoryStorage.
     *
     */
    this.clear = function() {
        if(applet)
            innerCert = this._innerStorage.clear();
        else
            innerCert = this._innerStorage.Clear();
    }
}

/********************************* Signer ************************************/

/**
 * A wrapper class around Signer class
 * Signer class signs a message and generaged PKCS#7 signed messages.
 *
 * @constructor
 */

function Signer() {
    //Keeps flavor
    var applet = (pkiBooster.flavor == "applet");

    //Wrapped signer object
    this._innerSigner = null;

    {
        if(applet)
            this._innerSigner = pkiBooster.pbObjFactory.createSigner();
        else
            this._innerSigner = new ActiveXObject("pkiactivex.Signer");
    }


    /**
     * Sets the storage that certificates and private keys stored to be used to
     * sign the message.
     *
     * @param Storage the storage. It may of different types.
     * @see PKCS11Storage
     * @see MemoryStorage
     * @see WinStorage
     */
    this.setStorage = function(Storage) {
        if(applet)
            this._innerSigner.setStorage(Storage._innerStorage);
        else
            this._innerSigner.Storage = Storage._innerStorage;
    }

    /**
     * Signs input data that is encoded in Base64 in returns signed data in PKCS#7
     * format and Base64 encoded.
     *
     * @param inString {String} Base64 encoded input data
     * @param detached {Boolean} Specifies whether the signature is detached or attached
     * @return {String} Signed Base64 encoded PKCS#7 message
     */
    this.sign = function (inString, detached) {
        var result = "";
        if(applet)
            result = this._innerSigner.sign(inString, detached);
        else
            result = this._innerSigner.Sign(inString, detached);
        return result;
    }

    /**
     * Returns hash algorithm used for sign.
     * @return {Number} hash algorithm
     */
    this.getHashAlgorithm = function () {
        var result = 0;
        if(applet)
            result = this._innerSigner.getHashAlgorithm();
        else
            result = this._innerSigner.HashAlgorithm;
        return result;
    }

    /**
     * Sets hash algorithm for sign.
     * @param {Number} algorithm the hash algorithm
     */
    this.setHashAlgorithm = function (algorithm) {
        if(applet)
            this._innerSigner.setHashAlgorithm(algorithm);
        else
            this._innerSigner.HashAlgorithm = algorithm;
    }
}
/********************************* Encryptor ************************************/

/**
 * A wrapper class around Encryptor class
 * Encryptor class encrypt a message and generate PKCS#7 encrypted messages.
 *
 * @constructor
 */

function Encryptor() {
    //Keeps flavor
    var applet = (pkiBooster.flavor == "applet");

    //Wrapped Encryptor object
    this._innerEncryptor = null;

    {
        if(applet)
            this._innerEncryptor = pkiBooster.pbObjFactory.createEncryptor();
        else
            this._innerEncryptor = new ActiveXObject("pkiactivex.Encryptor");
    }


    /**
     * Sets the storage that certificates stored to be used to
     * encrypt the message.
     *
     * @param Storage the storage. It may of different types.
     * @see PKCS11Storage
     * @see MemoryStorage
     * @see WinStorage
     */
    this.setStorage = function(Storage) {
        if(applet)
            this._innerEncryptor.setStorage(Storage._innerStorage);
        else
            this._innerEncryptor.Storage = Storage._innerStorage;
    }

    /**
     * Encrypt input data that is encoded in Base64 in returns encrypted data in PKCS#7
     * format and Base64 encoded.
     *
     * @param inString {String} Base64 encoded input data
     * @return {String} Encrypted Base64 encoded PKCS#7 message
     */
    this.encrypt = function (inString) {
        var result = "";
        if(applet)
            result = this._innerEncryptor.encrypt(inString);
        else
            result = this._innerEncryptor.Encrypt(inString);
        return result;
    }

    /**
     * Returns algorithm used for encrypt.
     * @return {Number} encryption algorithm
     */
    this.getAlgorithm = function () {
        var result = 0;
        if(applet)
            result = this._innerEncryptor.getAlgorithm();
        else
            result = this._innerEncryptor.Algorithm;
        return result;
    }

    /**
     * Sets algorithm for encrypt.
     * @param {Number} encryption algorithm number
     */
    this.setAlgorithm = function (algorithm) {
        if(applet)
            this._innerEncryptor.setAlgorithm(algorithm);
        else
            this._innerEncryptor.Algorithm = algorithm;
    }
    /**
     * Returns keyLength used for encrypt.
     * @return {Number} encryption key length
     */
    this.getKeyLength = function () {
        var result = 0;
        if(applet)
            result = this._innerEncryptor.getKeyLength();
        else
            result = this._innerEncryptor.KeyLength;
        return result;
    }

    /**
     * Sets encryption key length.
     * @param keyLength {Number} encryption key length
     */
    this.setKeyLength = function (keyLength) {
        if(applet)
            this._innerEncryptor.setKeyLength(keyLength);
        else
            this._innerEncryptor.KeyLength = keyLength;
    }
}

/********************************* Decryptor ************************************/

/**
 * A wrapper class around Decryptor class
 * Decryptor class Decrypt a PKCS#7 encrypted message and generate plain messages in Base64 encoded format.
 *
 * @constructor
 */

function Decryptor() {
    //Keeps flavor
    var applet = (pkiBooster.flavor == "applet");

    //Wrapped Decryptor object
    this._innerDecryptor = null;

    {
        if(applet)
            this._innerDecryptor = pkiBooster.pbObjFactory.createDecryptor();
        else
            this._innerDecryptor = new ActiveXObject("pkiactivex.Decryptor");
    }


    /**
     * Sets the storage that certificates and private keys stored to be used to
     * decrypt the message.
     *
     * @param Storage the storage. It may of different types.
     * @see PKCS11Storage
     * @see MemoryStorage
     * @see WinStorage
     */
    this.setStorage = function(Storage) {
        if(applet)
            this._innerDecryptor.setStorage(Storage._innerStorage);
        else
            this._innerDecryptor.Storage = Storage._innerStorage;
    }

    /**
     * Decrypt input encrypted data in PKCS#7 in returns plain data as
     * Base64 encoded format.
     *
     * @param encryptedData {String} PKCS#7 encrypted data that needs to be decrypted
     * @return {String} Base64 encoded plain data
     */
    this.decrypt = function (encryptedData) {
        var result = "";
        if(applet)
            result = this._innerDecryptor.decrypt(encryptedData);
        else
            result = this._innerDecryptor.Decrypt(encryptedData);
        return result;
    }

    /**
     * Returns algorithm used for encryption.
     * @return {Number} encryption algorithm
     */
    this.getAlgorithm = function () {
        var result = 0;
        if(applet)
            result = this._innerDecryptor.getAlgorithm();
        else
            result = this._innerDecryptor.Algorithm;
        return result;
    }
}

/********************************* Verifier ************************************/

/**
 * A wrapper class around Verifier class
 * Verifier class Verify a Signed message.
 *
 * @constructor
 */

function Verifier() {
    //Keeps flavor
    var applet = (pkiBooster.flavor == "applet");

    //Wrapped verifier object
    this._innerVerifier = null;

    {
        if(applet)
            this._innerVerifier = pkiBooster.pbObjFactory.createVerifier();
        else
            this._innerVerifier = new ActiveXObject("pkiactivex.Verifier");
    }


    /**
     * Sets the storage that certificate stored to be used to Verify the signed message.
     *
     * @param Storage the storage. It may of different types.
     * @see PKCS11Storage
     * @see MemoryStorage
     * @see WinStorage
     */
    this.setStorage = function(Storage) {
        if(applet)
            this._innerVerifier.setStorage(Storage._innerStorage);
        else
            this._innerVerifier.Storage = Storage._innerStorage;
    }

    /**
     * Verify input signed data that is encoded in Base64 in returns the message that was signed in Base64 encoded format.
     *
     * @param inString {String} Base64 encoded input signed data
     * @return {String} The plain Base64 encoded message if signed message verified successfully.
     */
    this.verify = function (inString) {
        var result = "";
        if(applet)
            result = this._innerVerifier.verify(inString);
        else
            result = this._innerVerifier.Verify(inString);
        return result;
    }

    /**
     * Verify input detached signed data that is encoded in Base64 in returns boolean value that specifies verification result.
     *
     * @param inString {String} Base64 encoded input plain data
     * @param sigString {String} Base64 encoded detached signed data
     * @return {Boolean} True if signed message verified successfully.
     */
    this.verifyDetached = function (inString,sigString) {
        var result = false;
        if(applet)
            result = this._innerVerifier.verifyDetached(inString,sigString);
        else
            result = this._innerVerifier.VerifyDetached(inString,sigString);
        return result;
    }

    /**
     * Returns a MemoryStorage that contains certificates which exported from
     * signed message PKCS#7 package after verifying signed message
     * @return {MemoryStorage} a MemoryStorage that contains certificates
     */
    this.getCertificates = function () {
        var result = 0;
        if(applet)
            result = this._innerVerifier.getCertificates();
        else
            result = this._innerVerifier.Certificates;
        return result;
    }
}


/********************************* Certificate *******************************/

/**
 * Loads a certificate from der-encoded Base64 string
 * @param base64 {String} base64 der-encoded Base64 certificate
 * @param password {String?} password for decrypting base64 encoded data
 * @return a @link{_Certificate} object
 */

function loadCerFromBase64(base64,password) {
    var cert = new _Certificate();
    if(!password)
        password = "";
    cert._loadFromBase64(base64,password);
    return cert;
}

/**
 * Loads X.509 certificate from file.
 *
 * @param {String} fileName path to certificate file
 * @param {String} password optional password
 * @return a @link{_Certificate} object
 */
function loadCertFromFile(fileName, password) {
    var cert = new _Certificate();
    cert._loadFromFile(fileName, password);
    return cert;
}

/**
 * A wrapper around Certificate class
 * Certificate class represents an X.509 certificate
 *
 * @private
 */
function _Certificate() {
    // Keeps flavor
    var applet = (pkiBooster.flavor == "applet");

    // Wrapped Certificate object
    this._innerCertificate = null;

    // Subject Name
    this._subjectName =  new _X500Name();

    // Issuer Name
    this._issuerName  =  new _X500Name();


    {
        if(!applet)
            this._innerCertificate = new ActiveXObject("pkiactivex.Certificate");
    }

    /**
     * Loads a certificate from der-encoded Base64 string
     * @param base64 {String} base64 der-encoded Base64 certificate
     * @param password {String} password for decrypting data
     */
    this._loadFromBase64 = function (base64,password) {
        if(applet)
            this._innerCertificate = pkiBooster.pbObjFactory.loadCertificateFromBase64(base64,password);
        else
            this._innerCertificate.LoadFromBase64(base64,password);
        this._loadInternals();
    }

    /**
     * Loads X.509 certificate from file.
     *
     * @param {String} fileName path to certificate file
     * @param {String} password optional password
     */
    this._loadFromFile = function (fileName, password) {
        if(applet)
            this._innerCertificate = pkiBooster.pbObjFactory.loadFromFile(fileName, password);
        else
            this._innerCertificate.LoadFromFile (fileName, password);
        this._loadInternals();
    }

    /**
     * This method loads internal objects for certificate object.
     * @private
     */
    this._loadInternals = function () {
        if(applet) {
            this._subjectName._innerX500Name = this._innerCertificate.getSubjectName();
            this._issuerName._innerX500Name = this._innerCertificate.getIssuerName();
        } else {
            this._subjectName._innerX500Name = this._innerCertificate.SubjectName;
            this._issuerName._innerX500Name = this._innerCertificate.IssuerName;
        }
    }

    /**
     * Returns certificate subject name.
     *
     * @return {_X500Name} certificate subject name
     */
    this.getSubjectName = function() {
        return this._subjectName;
    }

    /**
     * Returns certificate issuer name
     *
     * @return {_X500Name} certificate subject name
     */
    this.getIssuerName = function() {
        return this._issuerName;
    }

    /**
     * Valid from date
     * @return {Date} valid from date
     */
    this.getValidFrom = function() {
        if(applet)
            return new Date(this._innerCertificate.getValidFrom().getTime());
        else
            return new Date(this._innerCertificate.ValidFrom);
    }

    /**
     * Valid to date
     * @return {Date} valid to date
     */
    this.getValidTo = function() {
        if(applet)
            return new Date(this._innerCertificate.getValidTo().getTime());
        else
            return new Date(this._innerCertificate.ValidTo);
    }

    /**
     * Certificate serial number
     * @return {String} serial number
     */

    this.getSerialNumber = function() {
        if(applet)
            return this._innerCertificate.getSerialNumber();
        else
            return this._innerCertificate.SerialNumber;
    }

}

/********************************* X500Name **********************************/

/**
 * Wrapper around X500Name class
 * @private
 */
function _X500Name() {
    // Keeps flavor
    var applet = (pkiBooster.flavor == "applet");

    // Wrapped X500Name object
    this._innerX500Name = null;

    /**
     * Returns common name
     * @return {String} common name
     */
    this.getCommonName = function() {
        if(applet)
            return this._innerX500Name.getCommonName();
        else
            return this._innerX500Name.CommonName;
    }

    /**
     * Returns state
     * @return {String} state
     */

    this.getState = function() {
        if(applet)
            return this._innerX500Name.getState();
        else
            return this._innerX500Name.State;
    }

    /**
     * Returns locality
     * @return {String} locality
     */
    this.getLocality = function() {
        if(applet)
            return this._innerX500Name.getLocality();
        else
            return this._innerX500Name.Locality;
    }

    /**
     * Returns organization
     * @return {String} organization
     */
    this.getOrganization = function() {
        if(applet)
            return this._innerX500Name.getOrganization();
        else
            return this._innerX500Name.Organization;
    }

    /**
     * Returns organization unit
     * @return {String} organization unit
     */
    this.getOrganizationUnit = function() {
        if(applet)
            return this._innerX500Name.getOrganizationUnit();
        else
            return this._innerX500Name.OrganizationUnit;
    }

    /**
     * Returns country
     *
     * @return {String} country
     */
    this.getCountry = function() {
        if(applet)
            return this._innerX500Name.getCountry();
        else
            return this._innerX500Name.Country;
    }

    /**
     * Returns email address
     * @return {String} email address
     */
    this.getEmailAddress = function() {
        if(applet)
            return this._innerX500Name.getEmailAddress();
        else
            return this._innerX500Name.EmailAddress;
    }
}

/********************************* CryptoProvider ****************************/

/**
 * Wrapper around CryptoProvider.
 * It is a cryptographic service provider.
 *
 * @private
 */

function _CryptoProvider() {
    this._innerCryptoProvider = null;
}

/********************************* RSAKeyMaterial ****************************/

// Reference to RSAKeyMaterialFactory from COM library
var _innerRSAKeyMaterialFactory = null;

/**
 * Wrapper around RSAKeyMaterial class
 * It represents an RSA key material
 * @param {_CryptoProvider} cryptoProvider cryptographic service provider that
 * generates and keeps the key.
 *
 * @constructor
 */

function RSAKeyMaterial(cryptoProvider) {
    // Keeps flavor
    var applet = pkiBooster.flavor == "applet";

    // Wrapped RSAKeyMaterial object
    this._innerRSAKeyMaterial = null;

    {
        if(applet)
            this._innerRSAKeyMaterial = pkiBooster.pbObjFactory.createRSRsaKeyMaterial(cryptoProvider._innerCryptoProvider);
        else {
            if(_innerRSAKeyMaterialFactory == null)
                _innerRSAKeyMaterialFactory = new ActiveXObject("pkiactivex.RSAKeyMaterialFactory");
            this._innerRSAKeyMaterial = _innerRSAKeyMaterialFactory.CreateInstance(cryptoProvider._innerCryptoProvider);
        }
    }

    /**
     * Generates an RSA keypair
     * @param {Number} bits number of bits in RSA keypair
     */
    this.generate = function(bits) {
        if(applet)
            this._innerRSAKeyMaterial.generate(bits);
        else
            this._innerRSAKeyMaterial.Generate(bits);
    }
}


/********************************* Util **************************************/

/**
 * Wrapper around Util class
 *
 * @constructor
 */

function Util() {
    // Keeps flavor
    var applet = pkiBooster.flavor == "applet";

    // Wrapped Util object
    this._innerUtil = null;

    {
        if(applet)
            this._innerUtil = pkiBooster.pbObjFactory.createUtil();
        else {
            this._innerUtil = new ActiveXObject("pkiactivex.Util");
        }
    }

    /**
     * Convert a hex encoded binary data to a Base64 encoded binary data
     * @param hexString hex encoded data
     * @return {String} Base64 encoded data
     */

    this.hexStringToBase64 = function(hexString) {
        if(applet)
            return this._innerUtil.hexStringToBase64(hexString);
        else
            return this._innerUtil.HexStringToBase64(hexString);
    }


    /**
     * Converts a string UTF8 encoded binary data to Base64
     * @param inString the input string
     * @return {String} Base64 encoded data
     */
    this.stringToBase64 = function(inString) {
        if(applet)
            return this._innerUtil.stringToBase64(inString);
        else
            return this._innerUtil.StringToBase64(inString);
    }

    /**
     * Converts a Base64 encoded string data to string UTF8 encoded data
     * @param inString the input Base64 encoded string data
     * @return {String} string UTF8 encoded data
     */
    this.base64ToString = function(inString) {
        if(applet)
            return this._innerUtil.base64ToString(inString);
        else
            return this._innerUtil.Base64ToString(inString);
    }
}


