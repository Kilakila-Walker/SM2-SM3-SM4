package com.security.cipher;

import org.bouncycastle.util.encoders.Hex;
/**
 * SM3工具类 获取SM3摘要
 * @author Walker
 *
 */
public class SM3Utils
{
	private static final String byteFormat="UTF-8";
	/** SM3值的长度 */
	private static final int BYTE_LENGTH = 32;
	
	/** SM3分组长度 */
	private static final int BLOCK_LENGTH = 64;
	
	/** 缓冲区长度 */
	private static final int BUFFER_LENGTH = BLOCK_LENGTH * 1;
	
	/** 缓冲区 */
	private byte[] xBuf = new byte[BUFFER_LENGTH];
	
	/** 缓冲区偏移量 */
	private int xBufOff;
	
	/** 初始向量 */
	private byte[] V = SM3.iv.clone();
	
	private int cntBlock = 0;
 
	public SM3Utils() {
	}
 
	public SM3Utils(SM3Utils t)
	{
		System.arraycopy(t.xBuf, 0, this.xBuf, 0, t.xBuf.length);
		this.xBufOff = t.xBufOff;
		System.arraycopy(t.V, 0, this.V, 0, t.V.length);
	}
	
	/**
	 * SM3结果输出
	 * 
	 * @param out 保存SM3结构的缓冲区
	 * @param outOff 缓冲区偏移量
	 * @return
	 */
	protected int doFinal(byte[] out, int outOff) 
	{
		byte[] tmp = doFinal();
		System.arraycopy(tmp, 0, out, 0, tmp.length);
		return BYTE_LENGTH;
	}
 
	protected void reset() 
	{
		xBufOff = 0;
		cntBlock = 0;
		V = SM3.iv.clone();
	}
 
	/**
	 * 明文输入
	 * 
	 * @param in
	 *            明文输入缓冲区
	 * @param inOff
	 *            缓冲区偏移量
	 * @param len
	 *            明文长度
	 */
	protected void update(byte[] in, int inOff, int len)
	{
		int partLen = BUFFER_LENGTH - xBufOff;
		int inputLen = len;
		int dPos = inOff;
		if (partLen < inputLen) 
		{
			System.arraycopy(in, dPos, xBuf, xBufOff, partLen);
			inputLen -= partLen;
			dPos += partLen;
			doUpdate();
			while (inputLen > BUFFER_LENGTH) 
			{
				System.arraycopy(in, dPos, xBuf, 0, BUFFER_LENGTH);
				inputLen -= BUFFER_LENGTH;
				dPos += BUFFER_LENGTH;
				doUpdate();
			}
		}
 
		System.arraycopy(in, dPos, xBuf, xBufOff, inputLen);
		xBufOff += inputLen;
	}
 
	protected void doUpdate() 
	{
		byte[] B = new byte[BLOCK_LENGTH];
		for (int i = 0; i < BUFFER_LENGTH; i += BLOCK_LENGTH) 
		{
			System.arraycopy(xBuf, i, B, 0, B.length);
			doHash(B);
		}
		xBufOff = 0;
	}
 
	private void doHash(byte[] B)
	{
		byte[] tmp = SM3.CF(V, B);
		System.arraycopy(tmp, 0, V, 0, V.length);
		cntBlock++;
	}
 
	private byte[] doFinal() 
	{
		byte[] B = new byte[BLOCK_LENGTH];
		byte[] buffer = new byte[xBufOff];
		System.arraycopy(xBuf, 0, buffer, 0, buffer.length);
		byte[] tmp = SM3.padding(buffer, cntBlock);
		for (int i = 0; i < tmp.length; i += BLOCK_LENGTH)
		{
			System.arraycopy(tmp, i, B, 0, B.length);
			doHash(B);
		}
		return V;
	}
 
	protected void update(byte in) 
	{
		byte[] buffer = new byte[] { in };
		update(buffer, 0, 1);
	}
	
	protected int getDigestSize() 
	{
		return BYTE_LENGTH;
	}
	/**
	 * 获取SM3摘要 大写
	 * @param text 需要摘要的文本
	 * @return
	 * @throws Exception
	 */
	public static String SM3Up(String text) throws Exception 
	{
		String rd="";
		byte[] md = new byte[32];
		byte[] msg1 = text.getBytes(byteFormat);
		SM3Utils sm3 = new SM3Utils();
		sm3.update(msg1, 0, msg1.length);
		sm3.doFinal(md, 0);
		rd = new String(Hex.encode(md),byteFormat);
		return rd.toUpperCase();
	}
	/**
	 * 获取SM3摘要 小写
	 * @param text 需要摘要的文本
	 * @return
	 * @throws Exception
	 */
	public static String SM3Low(String text) throws Exception 
	{
		String rd="";
		byte[] md = new byte[32];
		byte[] msg1 = text.getBytes(byteFormat);
		SM3Utils sm3 = new SM3Utils();
		sm3.update(msg1, 0, msg1.length);
		sm3.doFinal(md, 0);
		rd = new String(Hex.encode(md),byteFormat);
		return rd;
	}
	
//	public static void main(String[] args) 
//	{
//		try {
//			String test="ererfeiisgodsaskj*&&^中文";
//			String s = SM3Utils.SM3Low(test);
//			System.out.println(s);
//		}
//		catch (Exception e) 
//		{
//			e.printStackTrace();
//		}
//	}
	
}

