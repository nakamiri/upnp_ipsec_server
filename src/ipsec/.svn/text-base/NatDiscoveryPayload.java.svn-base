package ipsec;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import encrypt.BinaryHexConverter;

/**
 * NAT-Dペイロードクラス
 * @author Nakamiri
 *　値のHashは前のメッセージで交換したHash方式と用いる
 *　値の計算は　Value = Hash(init_cookie | resp_cookie | IP | Port)
 * "|"はデータを結合することを意味するらしい
 * 2個のメッセージがあるのは自分のIP:Portと受信したパケットのIP:Portを送るからなのかな
 */
public class NatDiscoveryPayload extends CommonPayload {

	/**
	 * 自分のNAT-Dペイロード生成コンストラクタ
	 * @param socket
	 * @param isakmp
	 * @throws UnknownHostException
	 * @throws NoSuchAlgorithmException
	 */
	public NatDiscoveryPayload (DatagramSocket socket, IsakmpHeader isakmp) throws UnknownHostException, NoSuchAlgorithmException {
		byte[] local_addr = InetAddress.getLocalHost().getAddress();
		short local_port = (short) socket.getLocalPort();
		
		byte[] cky_i = isakmp.getInit_cookie();
		byte[] cky_r = isakmp.getResp_cookie();
		
		int capacity = local_addr.length + 2 + cky_i.length + cky_r.length;
		
		ByteBuffer bw = ByteBuffer.allocate(capacity);
		
		bw.put(cky_i);
		bw.put(cky_r);
		bw.put(local_addr);
		bw.putShort(local_port);
		
		data = MessageDigest.getInstance("SHA-1").digest(bw.array());
	}
	
	/**
	 * 自身のNAT-Dペイロード生成
	 * @param sock
	 * @param init_cookie
	 * @param resp_cookie
	 * @throws UnknownHostException
	 * @throws NoSuchAlgorithmException
	 */
	public NatDiscoveryPayload (DatagramSocket sock, byte[] init_cookie, byte[] resp_cookie) throws UnknownHostException, NoSuchAlgorithmException {
		byte[] local_addr = InetAddress.getLocalHost().getAddress();
		short local_port = (short) sock.getPort();
		
		int capacity = local_addr.length + 2 + init_cookie.length + resp_cookie.length;
		
		ByteBuffer bw = ByteBuffer.allocate(capacity);
		bw.put(init_cookie);
		bw.put(resp_cookie);
		bw.put(local_addr);
		bw.putShort(local_port);
		
		data = MessageDigest.getInstance("SHA-1").digest(bw.array());
	}
	
	
	/**
	 * 宛先のNAT-Dペイロード生成
	 * @param sock
	 * @param init_cookie
	 * @param resp_cookie
	 * @throws NoSuchAlgorithmException
	 */
	public NatDiscoveryPayload (InetSocketAddress sock, byte[] init_cookie, byte[] resp_cookie) throws NoSuchAlgorithmException {
		byte[] remote_addr = sock.getAddress().getAddress();
		short remote_port = (short) sock.getPort();
		
		int capacity = remote_addr.length + 2 + init_cookie.length + resp_cookie.length;
		ByteBuffer bw = ByteBuffer.allocate(capacity);
		bw.put(init_cookie);
		bw.put(resp_cookie);
		bw.put(remote_addr);
		bw.putShort(remote_port);
		
		data = MessageDigest.getInstance("SHA-1").digest(bw.array());
	}
	
	/**
	 * 宛先のNAT-Dペイロード生成コンストラクタ
	 * @param pkt
	 * @param isakmp
	 * @throws NoSuchAlgorithmException
	 * @throws UnknownHostException
	 */
	public NatDiscoveryPayload (DatagramPacket pkt, IsakmpHeader isakmp) throws NoSuchAlgorithmException, UnknownHostException {
		byte[] remote_addr = pkt.getAddress().getAddress();
		short remote_port = (short) pkt.getPort();
		
		byte[] cky_i = isakmp.getInit_cookie();
		byte[] cky_r = isakmp.getResp_cookie();
		
		int capacity = remote_addr.length + 2 + cky_i.length + cky_r.length;
		ByteBuffer bw = ByteBuffer.allocate(capacity);
		bw.put(cky_i);
		bw.put(cky_r);
		bw.put(remote_addr);
		bw.putShort(remote_port);
		
		data = MessageDigest.getInstance("SHA-1").digest(bw.array());
	}
	
	public NatDiscoveryPayload(byte[] payload_byte) {
		super(payload_byte);
		
		payload_type = Payload.NAT_DISCOVERY_PAYLOAD;
	}
	
	public void outputNatDiscoveryPayload () {
		System.out.println("----- Nat Discovery Payload -----");
		System.out.println("next payload: " + next_payload);
		System.out.println("payload length: " + payload_length);
		System.out.println("Nonce Data: " + BinaryHexConverter.bytesToHexString(data));
		System.out.println("----- Nat Discovery Payload End -----");
	}

	@Override
	void outputValue() {
		outputNatDiscoveryPayload();
	}

}
