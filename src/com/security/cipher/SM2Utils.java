package com.security.cipher;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

/**
 * SM2工具
 * 加密/解密/生成密钥
 * 算法中全部使用UTF-8编码
 * @author Walker
 *
 */
public class SM2Utils 
{
	private static final String byteFormat="UTF-8";
	/**
	 * SM2签名
	 * @param userId 签名用户
	 * @param privateKey 私钥
	 * @param sourceData 原文本
	 * @return 签名文本
	 * @throws Exception
	 */
	public static String SM2Sign(String UID, String priKey, String srcData) throws Exception
	{
		if (priKey == null || priKey.length() == 0)
		{
			return null;
		}

		if (srcData == null || srcData.length() == 0)
		{
			return null;
		}
		if (UID == null || UID.length() == 0)
		{
			return null;
		}
		byte[] userId = UID.getBytes(byteFormat);
		byte[] privateKey=Util.stringToHexBytes(priKey);
		byte[] sourceData=srcData.getBytes(byteFormat);
		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(privateKey);
		ECPoint userKey = sm2.ecc_point_g.multiply(userD);

		SM3Utils sm3 = new SM3Utils();
		byte[] z = sm2.sm2GetZ(userId, userKey);
		
		sm3.update(z, 0, z.length);
		sm3.update(sourceData, 0, sourceData.length);
		byte[] md = new byte[32];
		sm3.doFinal(md, 0);

		SM2Result sm2Result = new SM2Result();
		sm2.sm2Sign(md, userD, userKey, sm2Result);

		DERInteger d_r = new DERInteger(sm2Result.r);
		DERInteger d_s = new DERInteger(sm2Result.s);
		ASN1EncodableVector v2 = new ASN1EncodableVector();
		v2.add(d_r);
		v2.add(d_s);
		DERObject sign = new DERSequence(v2);
		byte[] signdata = sign.getDEREncoded();
		return new String(Base64.encode(signdata),byteFormat);
	}

	/**
	 * SM2签名验证
	 * @param userId 签名用户
	 * @param publicKey 公钥
	 * @param sourceData 原文本
	 * @param sData 签名 文本
	 * @return 验证签名是否正确 
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
	public static boolean SM2VerifySign(String UID, String pubKey, String srcData, String sData) throws Exception
	{
		if (pubKey == null || pubKey.length() == 0)
		{
			return false;
		}

		if (srcData == null || srcData.length() == 0)
		{
			return false;
		}
		if (UID == null || UID.length() == 0)
		{
			return false;
		}
		if (sData == null || sData.length() == 0)
		{
			return false;
		}
		byte[] userId=UID.getBytes(byteFormat);
		byte[] publicKey=Util.stringToHexBytes(pubKey);
		byte[] sourceData=srcData.getBytes(byteFormat);
		byte[] signData=Util.stringToHexBytes(sData);

		SM2 sm2 = SM2.Instance();
		ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);

		SM3Utils sm3 = new SM3Utils();
		byte[] z = sm2.sm2GetZ(userId, userKey);
		sm3.update(z, 0, z.length);
		sm3.update(sourceData, 0, sourceData.length);
		byte[] md = new byte[32];
		sm3.doFinal(md, 0);

		ByteArrayInputStream bis = new ByteArrayInputStream(signData);
		ASN1InputStream dis = new ASN1InputStream(bis);
		DERObject derObj = dis.readObject();
		Enumeration<DERInteger> e = ((ASN1Sequence) derObj).getObjects();
		BigInteger r = ((DERInteger)e.nextElement()).getValue();
		BigInteger s = ((DERInteger)e.nextElement()).getValue();
		SM2Result sm2Result = new SM2Result();
		sm2Result.r = r;
		sm2Result.s = s;
		
		sm2.sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
		return sm2Result.r.equals(sm2Result.R);
	}
	/**
	 * 生成随机秘钥对
	 * 返回一个Map 
	 * publicKey 对应公钥
	 * privateKey 对应密钥
	 */
	public static Map<String,String> generateKeyPair() throws Exception
	{
		SM2 sm2 = SM2.Instance();
		AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();
		ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
		ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
		BigInteger privateKey = ecpriv.getD();
		ECPoint publicKey = ecpub.getQ();
		Map<String,String> keys=new HashMap<String,String>();
		keys.put("publicKey", Util.hexBytesToString(publicKey.getEncoded()));
		keys.put("privateKey", Util.hexBytesToString(privateKey.toByteArray()));
		return keys;
	}
	
	/**
	 * 数据加密
	 * @param publicKey 公钥 
	 * @param data 加密数据
	 * @return
	 * @throws IOException
	 */
	private static String encrypt(byte[] publicKey, byte[] data) throws IOException
	{
		if (publicKey == null || publicKey.length == 0)
		{
			return null;
		}
		
		if (data == null || data.length == 0)
		{
			return null;
		}
		
		byte[] source = new byte[data.length];
		System.arraycopy(data, 0, source, 0, data.length);
		
		Cipher cipher = new Cipher();
		SM2 sm2 = SM2.Instance();
		ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);
		
		ECPoint c1 = cipher.Init_enc(sm2, userKey);
		cipher.Encrypt(source);
		byte[] c3 = new byte[32];
		cipher.Dofinal(c3);
		return Util.byteToHex(c1.getEncoded()) + Util.byteToHex(source) + Util.byteToHex(c3);
		
	}
	/**
	 * 数据解密
	 * @param privateKey 私钥
	 * @param encryptedData 加密过的数据
	 * @return
	 * @throws IOException
	 */
	private static byte[] decrypt(byte[] privateKey, byte[] encryptedData) throws IOException
	{
		if (privateKey == null || privateKey.length == 0)
		{
			return null;
		}
		
		if (encryptedData == null || encryptedData.length == 0)
		{
			return null;
		}
		String data = Util.byteToHex(encryptedData);
		byte[] c1Bytes = Util.hexToByte(data.substring(0,130));
		int c2Len = encryptedData.length - 97;
		byte[] c2 = Util.hexToByte(data.substring(130,130 + 2 * c2Len));
		byte[] c3 = Util.hexToByte(data.substring(130 + 2 * c2Len,194 + 2 * c2Len));
		
		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(1, privateKey);
		
		ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);
		Cipher cipher = new Cipher();
		cipher.Init_dec(userD, c1);
		cipher.Decrypt(c2);
		cipher.Dofinal(c3);
		
		return c2;
	}
	/**
	 * SM2加密
	 * @param data 需要加密的数据
	 * @return 返回一个Map publicKey:私钥      privateKey:密钥      cipherText:加密后文本
	 * @throws Exception
	 */
	public static Map<String,String> SM2Encrypt(String data) throws Exception 
	{
		byte[] sourceData = data.getBytes(byteFormat);
		SM2 sm2 = SM2.Instance();
		AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();
		ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
		ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
		BigInteger privateKey = ecpriv.getD();
		ECPoint publicKey = ecpub.getQ();
		String cipherText = SM2Utils.encrypt(publicKey.getEncoded(), sourceData);
		

		Map<String,String> keys=new HashMap<String,String>();
		
		keys.put("publicKey", Util.hexBytesToString(publicKey.getEncoded()));
		keys.put("privateKey", Util.hexBytesToString(privateKey.toByteArray()));
		keys.put("cipherText", Util.hexStringToString(cipherText));
		return keys;
	}
	/**
	 * SM2解密
	 * @param privateKey 私钥
	 * @param cipherText 加密文本
	 * @return
	 * @throws Exception
	 */
	public static String SM2Decrypt(String privateKey,String cipherText) throws Exception 
	{
		byte[] priKey=Util.stringToHexBytes(privateKey);
		byte[] cipherTxt=Util.stringToHexBytes(cipherText);
		String plainText = new String(SM2Utils.decrypt(priKey, cipherTxt),byteFormat);
		return plainText;
	}
	
//	public static void main(String[] args) throws Exception 
//	{
//		Map<String,String> m=SM2Utils.generateKeyPair();
//		String plainText = "asjdhjs山爸爸说你爸说你爸说你^877(*&!~";
//
//		Map<String,String> test= SM2Utils.SM2Encrypt(plainText);
//		System.out.println("公钥: "+test.get("publicKey").toString());
//		System.out.println("私钥: "+test.get("privateKey").toString());
//		System.out.println("密文: "+test.get("cipherText").toString());
//		
//		String encodeText=SM2Utils.SM2Decrypt(test.get("privateKey").toString(), test.get("cipherText").toString());
//		System.out.println("明文: "+encodeText);
//		
//        
//        // 国密规范测试私钥
//        String prikS = m.get("privateKey").toString();
//        System.out.println("私钥: " + prikS);
//        System.out.println("");
//
//        // 国密规范测试用户ID
//        String userId = "ALICE123@YAHOO.COM";
//
//        System.out.println("ID: " + Util.getHexString(userId.getBytes()));
//        System.out.println("");
//
//        System.out.println("签名: ");
//        String c = SM2Utils.SM2Sign(userId, prikS, plainText);
//        System.out.println("签名结果: " + c);
//        System.out.println("");
//
//        // 国密规范测试公钥
//        String pubkS = m.get("publicKey").toString();
//        System.out.println("公钥: " + pubkS);
//        System.out.println("");
//
//
//        System.out.println("验签: ");
//        boolean vs = SM2Utils.SM2VerifySign(userId, pubkS, plainText, c);
//        System.out.println("验签结果: " + vs);
//        System.out.println("");
//
//	}
	
}

