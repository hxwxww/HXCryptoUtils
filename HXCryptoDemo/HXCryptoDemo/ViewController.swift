//
//  ViewController.swift
//  HXCryptoDemo
//
//  Created by HongXiangWen on 2019/7/5.
//  Copyright © 2019 WHX. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        print("\n===== Test base64 =====")
        let base64OriginString = "hello crypto!"
        print("base64OriginString: \(base64OriginString)")
        let base64EncodeString = HXCryptoUtils.base64EncodeFromString(base64OriginString)!
        print("base64EncodeString: \(base64EncodeString)")
        let base64DecodeString = HXCryptoUtils.base64DecodeFromString(base64EncodeString)!
        print("base64DecodeString: \(base64DecodeString)")
        
        print("\n===== Test MD5 =====")
        let MD5OriginString = "hello crypto!"
        print("MD5OriginString: \(MD5OriginString)")
        let MD5String = HXCryptoUtils.MD5StringFromString(MD5OriginString)
        print("MD5String: \(MD5String)")

        print("\n===== Test SHA1 =====")
        let SHA1OriginString = "hello crypto!"
        print("SHA1OriginString: \(SHA1OriginString)")
        let SHA1String = HXCryptoUtils.SHA1StringFromString(SHA1OriginString)
        print("SHA1String: \(SHA1String)")
        
        print("\n===== Test SHA224 =====")
        let SHA224OriginString = "hello crypto!"
        print("SHA224OriginString: \(SHA224OriginString)")
        let SHA224String = HXCryptoUtils.SHA224StringFromString(SHA224OriginString)
        print("SHA224String: \(SHA224String)")
        
        print("\n===== Test SHA256 =====")
        let SHA256OriginString = "hello crypto!"
        print("SHA256OriginString: \(SHA256OriginString)")
        let SHA256String = HXCryptoUtils.SHA256StringFromString(SHA256OriginString)
        print("SHA256String: \(SHA256String)")
        
        print("\n===== Test SHA384 =====")
        let SHA384OriginString = "hello crypto!"
        print("SHA384OriginString: \(SHA384OriginString)")
        let SHA384String = HXCryptoUtils.SHA384StringFromString(SHA384OriginString)
        print("SHA384String: \(SHA384String)")
        
        print("\n===== Test SHA512 =====")
        let SHA512OriginString = "hello crypto!"
        print("SHA512OriginString: \(SHA512OriginString)")
        let SHA512String = HXCryptoUtils.SHA512StringFromString(SHA512OriginString)
        print("SHA512String: \(SHA512String)")
        
        print("\n===== Test HMAC =====")
        let hmacOriginString = "hello crypto!"
        let hmacKeyString = "whx"
        print("hmacOriginString: \(hmacOriginString) hmacKey: \(hmacKeyString)")
        let hmacCryptoString = HXCryptoUtils.hexStringFromData(HXCryptoUtils.hmacFromString(hmacOriginString, algorithm: .SHA256, key: hmacKeyString))
        print("hmacCryptoString: \(hmacCryptoString)")
        
        
        print("\n===== Test RSA =====")
//        HXCryptoUtils.deleteRSAKeypairFromKeychain()
        var keypair = HXCryptoUtils.getRSAKeypairFromKeychain()
        if keypair == nil {
            keypair = HXCryptoUtils.generateRSAKeypair()
        }
        let RSAPlainString = "2341234567823412345678234123456782341234567823412345678---23412345678=====2341234567823412345678234123456782341234567823412345678----=====23412345678===========23412345678234123456782341234567823412345678-----=========="
        print("RSAPlainString: \(RSAPlainString)")
        let RSAEncryptedString = HXCryptoUtils.RSAEncrypt(keypair!.publicKey, plainText: RSAPlainString)!
        print("RSAEncryptedString: \(RSAEncryptedString)")
        let RSADecryptString = HXCryptoUtils.RSADecrypt(keypair!.privateKey, cipherText: RSAEncryptedString)!
        print("RSADecryptString: \(RSADecryptString)")
        
        let RSASignString = "123456789"
        let RSASignature = HXCryptoUtils.RSASign(keypair!.privateKey, message: RSASignString)!
        print("RSASignature: \(RSASignature)")
        let result = HXCryptoUtils.RSAVerify(keypair!.publicKey, message: RSASignString, signature: RSASignature)
        print(result ? "verify success" : "verify fail")
        
        print("\n===== Test AES =====")
        let AESKeyString = "whx"
        let AESPlainString = "23412345674----"
        print("AESPlainString: \(AESPlainString)")
        let AESEncryptedString = HXCryptoUtils.AESEncrypt(AESPlainString, key: AESKeyString)!
        print("AESEncryptedString: \(AESEncryptedString)")
        let AESDecryptString = HXCryptoUtils.AESDecrypt(AESEncryptedString, key: AESKeyString)!
        print("AESDecryptString: \(AESDecryptString)")
    }
    
}

