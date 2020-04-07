package com.security.cipher;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Base64;
//import java.util.UUID;  
/**
 * SM加解密 
 * @author Walker
 *
 */
public class SM4Utils
{
	protected String secretKey = "";
	protected String iv = "";
	protected String mode="ECB";
	protected boolean hexString=false;
	private static final String byteFormat="UTF-8";
	/**
	 * 不推荐使用无参构造
	 * 使用无参构造需之后设定相关参数才能使用!
	 */
	@Deprecated
	public SM4Utils()
	{
	}
	/**
	 * 初始化SM4加密
	 * !!!注意:hexStr为true时,密码与IV为32位GUID,hexStr为false时,密码与IV为16位"纯英文"字符
	 * @param sec 密码
	 * @param IV IV值(CBC模式必填) 
	 * @param mode ECB/CBC
	 * @param hexStr 密码与IV是否为十六进制的32字符串(如无"-"的GUID)
	 */
	public SM4Utils(String sec,String IV,String md,boolean hexStr)
	{
		this.secretKey=sec;
		this.iv=IV;
		this.mode=md.toUpperCase();
		this.hexString=hexStr;
	}
	/**
	 * 初始化SM4加密  (ECB模式)
	 * !!!注意:hexStr为true时,密码与IV为32位GUID,hexStr为false时,密码与IV为16位"纯英文"字符
	 * @param sec 密码 必填
	 * @param hexStr 密码与IV是否为十六进制的32字符串(如无"-"的GUID)
	 */
	public SM4Utils(String sec,boolean hexStr) {
		this.secretKey=sec;
		this.mode="ECB";
		this.iv="";
		this.hexString=hexStr;
	}
	/**
	 * ECB加密
	 * @param plainText 待加密文本
	 * @return
	 */
	public String SM4Encrypt_ECB(String plainText) throws Exception
	{
		if(mode.equals(""))
			throw new Exception("加密模式不能为空");
		if(!mode.equals("ECB") && !mode.equals("CBC"))
			throw new Exception("未定义的加密模式(加密模式可为:CBC/ECB)");
		if(!mode.equals("ECB"))
			throw new Exception("此方法为ECB加密");
		if(secretKey.equals(""))
			throw new Exception("密码不能为空");
		if(mode.equals("CBC") && iv.equals(""))
			throw new Exception("CBC模式下必须定义IV值");
		try 
		{
			SM4Context ctx = new SM4Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_ENCRYPT;
			
			byte[] keyBytes;
			if (hexString)
			{
				keyBytes = Util.hexStringToBytes(secretKey);
			}
			else
			{
				keyBytes = secretKey.getBytes(byteFormat);
			}
			
			SM4 sm4 = new SM4();
			sm4.sm4_setkey_enc(ctx, keyBytes);
			byte[] encrypted = sm4.sm4_crypt_ecb(ctx, plainText.getBytes(byteFormat));
			String cipherText=Base64.getEncoder().encodeToString(encrypted);
			if (cipherText != null && cipherText.trim().length() > 0)
			{
				Pattern p = Pattern.compile("\\s*|\t|\r|\n");
				Matcher m = p.matcher(cipherText);
				cipherText = m.replaceAll("");
			}
			return cipherText;
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			return null;
		}
	}
	/**
	 * ECB解密
	 * @param cipherText 待解密文本
	 * @return
	 */
	public String SM4Decrypt_ECB(String cipherText) throws Exception
	{

		if(mode.equals(""))
			throw new Exception("加密模式不能为空");
		if(!mode.equals("ECB") && !mode.equals("CBC"))
			throw new Exception("未定义的加密模式(加密模式可为:CBC/ECB)");
		if(!mode.equals("ECB"))
			throw new Exception("此方法为ECB解密");
		if(secretKey.equals(""))
			throw new Exception("密码不能为空");
		if(mode.equals("CBC") && iv.equals(""))
			throw new Exception("CBC模式下必须定义IV值");
		try 
		{
			SM4Context ctx = new SM4Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_DECRYPT;
			
			byte[] keyBytes;
			if (hexString)
			{
				keyBytes = Util.hexStringToBytes(secretKey);
			}
			else
			{
				keyBytes = secretKey.getBytes(byteFormat);
			}
			
			SM4 sm4 = new SM4();
			sm4.sm4_setkey_dec(ctx, keyBytes);
			byte[] decrypted = sm4.sm4_crypt_ecb(ctx, Base64.getDecoder().decode(cipherText));
			return new String(decrypted, byteFormat);
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			return null;
		}
	}
	/**
	 * CBC加密
	 * @param plainText 待加密文本
	 * @return
	 */
	public String SM4Encrypt_CBC(String plainText) throws Exception
	{
		if(mode.equals(""))
			throw new Exception("加密模式不能为空");
		if(!mode.equals("ECB") && !mode.equals("CBC"))
			throw new Exception("未定义的加密模式(加密模式可为:CBC/ECB)");
		if(!mode.equals("CBC"))
			throw new Exception("此方法为CBC加密");
		if(secretKey.equals(""))
			throw new Exception("密码不能为空");
		if(mode.equals("CBC") && iv.equals(""))
			throw new Exception("CBC模式下必须定义IV值");
		try 
		{
			SM4Context ctx = new SM4Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_ENCRYPT;
			
			byte[] keyBytes;
			byte[] ivBytes;
			if (hexString)
			{
				keyBytes = Util.hexStringToBytes(secretKey);
				ivBytes = Util.hexStringToBytes(iv);
			}
			else
			{
				keyBytes = secretKey.getBytes(byteFormat);
				ivBytes = iv.getBytes(byteFormat);
			}
			
			SM4 sm4 = new SM4();
			sm4.sm4_setkey_enc(ctx, keyBytes);
			byte[] encrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, plainText.getBytes(byteFormat));
			
			String cipherText = Base64.getEncoder().encodeToString(encrypted);
			if (cipherText != null && cipherText.trim().length() > 0)
			{
				Pattern p = Pattern.compile("\\s*|\t|\r|\n");
				Matcher m = p.matcher(cipherText);
				cipherText = m.replaceAll("");
			}
			return cipherText;
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			return null;
		}
	}
	/**
	 * CBC解密
	 * @param cipherText 加密文本
	 * @return 解密文本
	 * @throws Exception
	 */
	public String SM4Decrypt_CBC(String cipherText) throws Exception
	{
		if(mode.equals(""))
			throw new Exception("加密模式不能为空");
		if(!mode.equals("ECB") && !mode.equals("CBC"))
			throw new Exception("未定义的加密模式(加密模式可为:CBC/ECB)");
		if(!mode.equals("CBC"))
			throw new Exception("此方法为CBC解密");
		if(secretKey.equals(""))
			throw new Exception("密码不能为空");
		if(mode.equals("CBC") && iv.equals(""))
			throw new Exception("CBC模式下必须定义IV值");
		try 
		{
			SM4Context ctx = new SM4Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_DECRYPT;
			
			byte[] keyBytes;
			byte[] ivBytes;
			if (hexString)
			{
				keyBytes = Util.hexStringToBytes(secretKey);
				ivBytes = Util.hexStringToBytes(iv);
			}
			else
			{
				keyBytes = secretKey.getBytes(byteFormat);
				ivBytes = iv.getBytes(byteFormat);
			}
			
			SM4 sm4 = new SM4();
			sm4.sm4_setkey_dec(ctx, keyBytes);
			byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, Base64.getDecoder().decode(cipherText));
			return new String(decrypted, byteFormat);
		} 
		catch (Exception e)
		{
			e.printStackTrace();
			return null;
		}
	}
	/**
	 * SM4加密
	 * @param text 待加密文本
	 * @return 加密文本
	 * @throws Exception
	 */
	public String SM4Encrypt(String text) throws Exception
	{
		String rd="";
		if(mode.equals(""))
			throw new Exception("加密模式不能为空");
		if(!mode.equals("ECB") && !mode.equals("CBC"))
			throw new Exception("未定义的加密模式(加密模式可为:CBC/ECB)");
		if(secretKey.equals(""))
			throw new Exception("密码不能为空");
		if(mode.equals("CBC") && iv.equals(""))
			throw new Exception("CBC模式下必须定义IV值");
		if(mode.equals("ECB"))
			rd=SM4Encrypt_ECB(text);
		else if(mode.equals("CBC") && !iv.equals(""))
			rd=SM4Encrypt_CBC(text);
		return rd;
	}
	/**
	 * SM4解密
	 * @param secText 加密文本
	 * @return 原文本
	 * @throws Exception
	 */
	public String SM4Decrypt(String secText) throws Exception
	{
		String rd="";
		if(mode.equals(""))
			throw new Exception("加密模式不能为空");
		if(!mode.equals("ECB") && !mode.equals("CBC"))
			throw new Exception("未定义的加密模式(加密模式可为:CBC/ECB)");
		if(secretKey.equals(""))
			throw new Exception("密码不能为空");
		if(mode.equals("CBC") && iv.equals(""))
			throw new Exception("CBC模式下必须定义IV值");
		if(mode.equals("ECB"))
			rd=SM4Decrypt_ECB(secText);
		else if(mode.equals("CBC") && !iv.equals(""))
			rd=SM4Decrypt_CBC(secText);
		return rd;
	}
	
//	public static void main(String[] args) throws Exception 
//	{
//		UUID uuid = UUID.randomUUID(); 
//		String txt=uuid.toString().replace("-", "");
//		String plainText = "这是中文加密";
//		SM4Utils sm4 = new SM4Utils(txt,txt,"ecb",true);
//		String se=sm4.SM4Encrypt(plainText);
//		System.out.println("密文: " + se);
//		String tx=sm4.SM4Decrypt(se);
//		System.out.println("明文: " + tx);
//		  
//		System.out.println("ECB模式");
//		String cipherText = sm4.SM4Encrypt_ECB(plainText);
//		System.out.println("密文: " + cipherText);
//		System.out.println("");
//		
//		plainText = sm4.SM4Decrypt_ECB(cipherText);
//		System.out.println("明文: " + plainText);
//		System.out.println("");
//		
//		System.out.println("CBC模式");
//		cipherText = sm4.SM4Encrypt_CBC(plainText);
//		System.out.println("密文: " + cipherText);
//		System.out.println("");
//		
//		plainText = sm4.SM4Decrypt_CBC(cipherText);
//		System.out.println("明文: " + plainText);
//	}
}
