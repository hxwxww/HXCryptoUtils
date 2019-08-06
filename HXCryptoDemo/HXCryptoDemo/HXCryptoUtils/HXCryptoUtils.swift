//
//  HXCryptoUtils.swift
//  HXCryptoDemo
//
//  Created by HongXiangWen on 2019/7/5.
//  Copyright © 2019 WHX. All rights reserved.
//

import Foundation
import CommonCrypto

// MARK: -  加解密工具类

// MARK: -  哈希/散列算法
class HXCryptoUtils {
    
    // MARK: -  hash算法类型
    enum HXHashAlgorithm {
        
        case MD5
        case SHA1
        case SHA224
        case SHA256
        case SHA384
        case SHA512
        
        var digestLength: Int {
            switch self {
            case .MD5:
                return Int(CC_MD5_DIGEST_LENGTH)
            case .SHA1:
                return Int(CC_SHA1_DIGEST_LENGTH)
            case .SHA224:
                return Int(CC_SHA224_DIGEST_LENGTH)
            case .SHA256:
                return Int(CC_SHA256_DIGEST_LENGTH)
            case .SHA384:
                return Int(CC_SHA384_DIGEST_LENGTH)
            case .SHA512:
                return Int(CC_SHA512_DIGEST_LENGTH)
            }
        }
        
        var hmacAlgorithm: CCHmacAlgorithm {
            switch self {
            case .MD5:
                return CCHmacAlgorithm(kCCHmacAlgMD5)
            case .SHA1:
                return CCHmacAlgorithm(kCCHmacAlgSHA1)
            case .SHA224:
                return CCHmacAlgorithm(kCCHmacAlgSHA224)
            case .SHA256:
                return CCHmacAlgorithm(kCCHmacAlgSHA256)
            case .SHA384:
                return CCHmacAlgorithm(kCCHmacAlgSHA384)
            case .SHA512:
                return CCHmacAlgorithm(kCCHmacAlgSHA512)
            }
        }
        
    }
    
    /// MD5算法，MD5是单向的，只能加密不能解密。严格来说，MD5不是一种加密算法而是摘要算法。
    ///【MD5加密特点】：
    /// 1、压缩性：任意长度的数据，算出的MD5值长度都是固定的。
    /// 2、容易计算：从原数据计算出MD5值很容易。
    /// 3、抗修改性：对原数据进行任何改动，哪怕只修改1个字节，所得到的MD5值都有很大区别。
    /// 4、强抗碰撞：已知原数据和其MD5值，想找到一个具有相同MD5值的数据（即伪造数据）是非常困难的。
    ///
    /// - Parameter str: 目标字符串
    /// - Returns: 加密后的字符串
    static func MD5StringFromString(_ str: String) -> String {
        return hexStringFromData(hashFromString(str, algorithm: .MD5))
    }
    
    /// SHA1是和MD5一样流行的消息摘要算法，然而SHA1比MD5的安全性更强。对于长度小于2^64位的消息，SHA1会产生一个160位的
    /// 消息摘要。基于MD5、SHA1的信息摘要特性以及不可逆(一般而言)，可以被应用在检查文件完整性以及数字签名等场景。
    ///
    /// - Parameter str: 目标字符串
    /// - Returns: 加密后的字符串
    static func SHA1StringFromString(_ str: String) -> String {
        return hexStringFromData(hashFromString(str, algorithm: .SHA1))
    }
    
    /// SHA224
    ///
    /// - Parameter str: 目标字符串
    /// - Returns: 加密后的字符串
    static func SHA224StringFromString(_ str: String) -> String {
        return hexStringFromData(hashFromString(str, algorithm: .SHA224))
    }
    
    /// SHA256
    ///
    /// - Parameter str: 目标字符串
    /// - Returns: 加密后的字符串
    static func SHA256StringFromString(_ str: String) -> String {
        return hexStringFromData(hashFromString(str, algorithm: .SHA256))
    }
    
    /// SHA384
    ///
    /// - Parameter str: 目标字符串
    /// - Returns: 加密后的字符串
    static func SHA384StringFromString(_ str: String) -> String {
        return hexStringFromData(hashFromString(str, algorithm: .SHA384))
    }
    
    /// SHA512
    ///
    /// - Parameter str: 目标字符串
    /// - Returns: 加密后的字符串
    static func SHA512StringFromString(_ str: String) -> String {
        return hexStringFromData(hashFromString(str, algorithm: .SHA512))
    }
    
    /// 计算hash
    ///
    /// - Parameters:
    ///   - str: 原字符串
    ///   - algorithm: 算法
    /// - Returns: 结果数据
    static func hashFromString(_ str: String, algorithm: HXHashAlgorithm) -> Data {
        let cStr = str.cString(using: .utf8)
        let strLen = CC_LONG(str.lengthOfBytes(using: .utf8))
        let digestLength = algorithm.digestLength
        let digest = UnsafeMutablePointer<UInt8>.allocate(capacity: digestLength)
        switch algorithm {
        case .MD5:
            CC_MD5(cStr, strLen, digest)
        case .SHA1:
            CC_SHA1(cStr, strLen, digest)
        case .SHA224:
            CC_SHA224(cStr, strLen, digest)
        case .SHA256:
            CC_SHA256(cStr, strLen, digest)
        case .SHA384:
            CC_SHA384(cStr, strLen, digest)
        case .SHA512:
            CC_SHA512(cStr, strLen, digest)
        }
        return Data(bytes: digest, count: digestLength)
    }
        
    /// HMAC是哈希运算消息认证码（Hash-based Message Authentication Code），HMAC运算利用哈希算法(MD5、SHA1等)，以
    /// 一个密钥和一个消息为输入，生成一个消息摘要作为输出。
    /// HMAC发送方和接收方都有的key进行计算，而没有这把key的第三方，则是无法计算出正确的散列值的，这样就可以防止数据被篡改。
    ///
    /// - Parameters:
    ///   - str: 目标字符串
    ///   - algorithm: 算法
    ///   - key: 密钥
    /// - Returns: hmac后的数据
    static func hmacFromString(_ str: String, algorithm: HXHashAlgorithm, key: String) -> Data {
        let kStr = key.cString(using: .utf8)
        let keyLen = CC_LONG(key.lengthOfBytes(using: .utf8))
        let cStr = str.cString(using: .utf8)
        let strLen = CC_LONG(str.lengthOfBytes(using: .utf8))
        let digestLength = algorithm.digestLength
        let digest = UnsafeMutablePointer<UInt8>.allocate(capacity: digestLength)
        CCHmac(algorithm.hmacAlgorithm, kStr, Int(keyLen), cStr, Int(strLen), digest)
        return Data(bytes: digest, count: digestLength)
    }
    
}

// MARK: -  base64
extension HXCryptoUtils {
    
    /// base64加密
    ///
    /// - Parameter str: 目标字符串
    /// - Returns: 加密后的字符串
    static func base64EncodeFromString(_ str: String) -> String? {
        guard let base64Data = str.data(using: .utf8) else { return nil }
        return base64Data.base64EncodedString()
    }
    
    /// base64解密
    ///
    /// - Parameter str: 目标字符串
    /// - Returns: 解密后的字符串
    static func base64DecodeFromString(_ str: String) -> String? {
        guard let base64Data = Data(base64Encoded: str) else { return nil }
        return String(data: base64Data, encoding: .utf8)
    }
    
}

// MARK: -  RSA
extension HXCryptoUtils {
    
    /// RSA算法有2个作用一个是加密一个是加签。
    /// 第一种是使用公钥加密，使用私钥解密。
    /// 第二种就是用私钥加签，使用公钥验签。
    /// 第一种完全是为了加密，第二种是为了防抵赖。
    
    /// 检索的凭证
    static let kPrivateKeyLabel = "com.whx.privateKey"
    static let kPublicKeyLabel = "com.whx.publicKey"
    
    /// 生成RSA密钥对，会直接持久化到钥匙串中
    ///
    /// - Parameter keySize: 支持512，768，1024，2048位，默认2048
    /// - Returns: 密钥对
    static func generateRSAKeypair(_ keySize: Int = 2048) -> (privateKey: SecKey, publicKey: SecKey)? {
        let attributes = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: keySize,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,  /// 持久化到钥匙串中
                kSecAttrLabel: kPrivateKeyLabel
            ],
            kSecPublicKeyAttrs: [
                kSecAttrIsPermanent: true,  /// 持久化到钥匙串中
                kSecAttrLabel: kPublicKeyLabel
            ]
            ] as CFDictionary
        if #available(iOS 10.0, *) {
            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(attributes, &error) else {
                print("Failed to generate RSA keypair: \(error!.takeRetainedValue().localizedDescription)")
                return nil
            }
            guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
                print("Failed to generate RSA keypair: copy public key from private key fail")
                return nil
            }
            return (privateKey, publicKey)
        } else {
            var privateKey: SecKey?
            var publicKey: SecKey?
            let status = SecKeyGeneratePair(attributes, &publicKey, &privateKey)
            guard status == errSecSuccess else {
                print("Failed to generate RSA keypair: \(status)")
                return nil
            }
            return (privateKey!, publicKey!)
        }
    }
    
    /// 从钥匙串中获取密钥对
    ///
    /// - Returns: 密钥对
    static func getRSAKeypairFromKeychain() -> (privateKey: SecKey, publicKey: SecKey)? {
        /// 读取私钥
        let privateKeyQuery = [
            kSecClass: kSecClassKey,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecAttrLabel: kPrivateKeyLabel,
            kSecReturnRef: true
            ] as CFDictionary
        var privateKeyType: CFTypeRef?
        let priStatus = SecItemCopyMatching(privateKeyQuery, &privateKeyType)
        guard priStatus == errSecSuccess else {
            print("Failed to get RSA private key: \(priStatus)")
            return nil
        }
        /// 读取公钥
        let publicKeyQuery = [
            kSecClass: kSecClassKey,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecAttrLabel: kPublicKeyLabel,
            kSecReturnRef: true
            ] as CFDictionary
        var publicKeyType: CFTypeRef?
        let pubStatus = SecItemCopyMatching(publicKeyQuery, &publicKeyType)
        guard pubStatus == errSecSuccess else {
            print("Failed to get RSA public key: \(pubStatus)")
            return nil
        }
        return (privateKeyType as! SecKey, publicKeyType as! SecKey)
    }
    
    /// 从钥匙串中删除密钥对
    static func deleteRSAKeypairFromKeychain() {
        /// 删除私钥
        let privateKeyQuery = [
            kSecClass: kSecClassKey,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrLabel: kPrivateKeyLabel,
            ] as CFDictionary
        let priStatus = SecItemDelete(privateKeyQuery)
        if (priStatus != errSecSuccess && priStatus != errSecItemNotFound) {
            print("Failed to remove private key: \(priStatus)")
        }
        /// 删除公钥
        let publickKeyQuery = [
            kSecClass: kSecClassKey,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrLabel: kPublicKeyLabel,
            ] as CFDictionary
        let pubStatus = SecItemDelete(publickKeyQuery)
        if (pubStatus != errSecSuccess && pubStatus != errSecItemNotFound) {
            print("Failed to remove public key: \(pubStatus)")
        }
    }
    
    /// 使用公钥加密
    ///
    /// - Parameters:
    ///   - publicKey: 公钥
    ///   - plainText: 明文
    /// - Returns: 密文
    static func RSAEncrypt(_ publicKey: SecKey, plainText: String) -> String? {
        guard let plainData = plainText.data(using: .utf8) else {
            print("Failed to encrypt RSA: plainText cannot be converted to utf8 data")
            return nil
        }
        let totalLength = plainData.count
        let blockLength = SecKeyGetBlockSize(publicKey)
        var cipherBuffer = [UInt8](repeating: 0, count: blockLength)
        var cipherLength = blockLength
        var index = 0
        var cipherData = Data()
        while index < totalLength {
            var currentDataLength = totalLength - index
            /// kSecPaddingNone  = 0, 要加密的数据块大小 <＝ SecKeyGetBlockSize的大小，如这里256
            /// kSecPaddingPKCS1 = 1, 要加密的数据块大小 <= 256-11
            /// kSecPaddingOAEP  = 2, 要加密的数据块大小 <= 256-42
            if currentDataLength > blockLength - 11 {
                currentDataLength = blockLength - 11
            }
            let currentData = plainData.subdata(in: index ..< index + currentDataLength)
            var subCipherData: Data
            if #available(iOS 10.0, *) {
                var error: Unmanaged<CFError>?
                guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionPKCS1, currentData as CFData, &error) else {
                    print("Failed to encrypt RSA: \(error!.takeRetainedValue().localizedDescription)")
                    return nil
                }
                subCipherData = encryptedData as Data
            } else {
                let status = SecKeyEncrypt(publicKey, .PKCS1, [UInt8](currentData), currentDataLength, &cipherBuffer, &cipherLength)
                guard status == errSecSuccess else {
                    print("Failed to encrypt RSA: \(status)")
                    return nil
                }
                subCipherData = Data(bytes: cipherBuffer, count: cipherLength)
            }
            cipherData.append(subCipherData)
            index += currentDataLength
        }
        return cipherData.base64EncodedString()
    }
    
    /// 使用私钥解密
    ///
    /// - Parameters:
    ///   - privateKey: 私钥
    ///   - cipherText: 密文
    /// - Returns: 明文
    static func RSADecrypt(_ privateKey: SecKey, cipherText: String) -> String? {
        guard let cipherData = Data(base64Encoded: cipherText) else {
            print("Failed to decrypt RSA: cipherText cannot be converted to base64 data")
            return nil
        }
        let totalLength = cipherData.count
        let blockLength = SecKeyGetBlockSize(privateKey)
        var plainBuffer = [UInt8](repeating: 0, count: blockLength)
        var plainLength = blockLength
        var index = 0
        var plainData = Data()
        while index < totalLength {
            var currentDataLength = totalLength - index
            if currentDataLength > blockLength {
                currentDataLength = blockLength
            }
            let currentData = cipherData.subdata(in: index ..< index + currentDataLength)
            var subPlainData: Data
            if #available(iOS 10.0, *) {
                var error: Unmanaged<CFError>?
                guard let encryptedData = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1, currentData as CFData, &error) else {
                    print("Failed to decrypt RSA: \(error!.takeRetainedValue().localizedDescription)")
                    return nil
                }
                subPlainData = encryptedData as Data
            } else {
                let status = SecKeyDecrypt(privateKey, .PKCS1, [UInt8](currentData), currentDataLength, &plainBuffer, &plainLength)
                guard status == errSecSuccess else {
                    print("Failed to decrypt RSA: \(status)")
                    return nil
                }
                subPlainData = Data(bytes: plainBuffer, count: plainLength)
            }
            plainData.append(subPlainData)
            index += currentDataLength
        }
        return String(data: plainData, encoding: .utf8)
    }
    
    /// 使用私钥签名
    ///
    /// - Parameters:
    ///   - privateKey: 私钥
    ///   - message: 要签名的数据
    /// - Returns: 签名的结果
    static func RSASign(_ privateKey: SecKey, message: String) -> String? {
        guard let msgData = message.data(using: .utf8) else {
            print("Failed to sign RSA: message cannot be converted to utf8 data")
            return nil
        }
        if #available(iOS 10.0, *) {
            var error: Unmanaged<CFError>?
            guard let sigData = SecKeyCreateSignature(privateKey, .rsaSignatureMessagePKCS1v15SHA256, msgData as CFData, &error) else {
                print("Failed to sign RSA: \(error!.takeRetainedValue().localizedDescription)")
                return nil
            }
            return (sigData as Data).base64EncodedString()
        } else {
            let SHA256Data = hashFromString(message, algorithm: .SHA256)
            var sigLength = SecKeyGetBlockSize(privateKey)
            var sigBuffer = [UInt8](repeating: 0, count: sigLength)
            let status = SecKeyRawSign(privateKey, .PKCS1SHA256, [UInt8](SHA256Data), SHA256Data.count, &sigBuffer, &sigLength)
            guard status == errSecSuccess else {
                print("Failed to sign RSA: \(status)")
                return nil
            }
            return Data(bytes: sigBuffer, count: sigLength).base64EncodedString()
        }
    }
    
    /// 使用公钥验证签名
    ///
    /// - Parameters:
    ///   - publicKey: 公钥
    ///   - message: 要签名的数据
    ///   - signature: 签名
    /// - Returns: 验证结果
    static func RSAVerify(_ publicKey: SecKey, message: String, signature: String) -> Bool {
        guard let msgData = message.data(using: .utf8) else {
            print("Failed to verify RSA: message cannot be converted to utf8 data")
            return false
        }
        guard let sigData = Data(base64Encoded: signature) else {
            print("Failed to verify RSA: signature cannot be converted to base64 data")
            return false
        }
        if #available(iOS 10.0, *) {
            var error: Unmanaged<CFError>?
            let result = SecKeyVerifySignature(publicKey, .rsaSignatureMessagePKCS1v15SHA256, msgData as CFData, sigData as CFData, &error)
            if !result {
                print("Failed to verify RSA: \(error!.takeRetainedValue().localizedDescription)")
            }
            return result
        } else {
            let SHA256Data = hashFromString(message, algorithm: .SHA256)
            let status = SecKeyRawVerify(publicKey, .PKCS1SHA256, [UInt8](SHA256Data), SHA256Data.count, [UInt8](sigData), sigData.count)
            guard status == errSecSuccess else {
                print("Failed to verify RSA: \(status)")
                return false
            }
            return true
        }
    }
    
}

// MARK: -  AES
extension HXCryptoUtils {
    
    /// AES加密
    ///
    /// - Parameters:
    ///   - plainText: 明文字符串
    ///   - key: 密钥字符串
    /// - Returns: 加密后的字符串（base64编码）
    static func AESEncrypt(_ plainText: String, key: String) -> String? {
        let keyStr = key.cString(using: .utf8)
        let plainStr = plainText.cString(using: .utf8)
        let plainLen = Int(CC_LONG(plainText.lengthOfBytes(using: .utf8)))
        let cipherLength = plainLen + kCCBlockSizeAES128
        var cipherBuffer = [UInt8](repeating: 0, count: cipherLength)
        var numBytesEncrypted: Int = 0
        let status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode), keyStr, kCCKeySizeAES128, nil, plainStr, Int(plainLen), &cipherBuffer, cipherLength, &numBytesEncrypted)
        guard status == kCCSuccess else {
            print("Failed to encrypt AES: \(status)")
            return nil
        }
        return Data(bytes: cipherBuffer, count: numBytesEncrypted).base64EncodedString()
    }
    
    /// AES解密
    ///
    /// - Parameters:
    ///   - cipherText: 密文字符串（base64编码）
    ///   - key: 密钥字符串
    /// - Returns: 解密后的字符串
    static func AESDecrypt(_ cipherText: String, key: String) -> String? {
        guard let cipherData = Data(base64Encoded: cipherText) else {
            print("Failed to decrypt AES: cipherText cannot be converted to base64 data")
            return nil
        }
        let keyStr = key.cString(using: .utf8)
        let cipherLength = cipherData.count
        let plainLength = cipherLength + kCCBlockSizeAES128
        var plainBuffer = [UInt8](repeating: 0, count: plainLength)
        var numBytesDecrypted: Int = 0
        let status = CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode), keyStr, kCCKeySizeAES128, nil, [UInt8](cipherData), cipherLength, &plainBuffer, plainLength, &numBytesDecrypted)
        guard status == kCCSuccess else {
            print("Failed to decrypt AES: \(status)")
            return nil
        }
        let plainData = Data(bytes: plainBuffer, count: numBytesDecrypted)
        return String(data: plainData, encoding: .utf8)
    }
    
}

// MARK: -  工具方法
extension HXCryptoUtils {
    
    /// data转16进制字符串
    ///
    /// - Parameter data: 数据
    /// - Returns: hexString
    static func hexStringFromData(_ data: Data) -> String {
        return data.withUnsafeBytes({ buffer in
            var hexString = ""
            for byte in buffer {
                hexString += String(format:"%02x", UInt8(byte))
            }
            return hexString
        })
    }
    
    /// 16进制字符串转data
    ///
    /// - Parameter hexString: 16进制字符串
    /// - Returns: data
    class func dataFromHexString(_ hexString: String) -> Data {
        var data = Data()
        for idx in 0 ..< hexString.count / 2 {
            let hex = (hexString as NSString).substring(with: NSRange(location: idx * 2, length: 2))
            let scanner = Scanner(string: hex)
            var intValue: UInt64 = 0
            scanner.scanHexInt64(&intValue)
            data.append(UInt8(intValue))
        }
        return data
    }
    
}
