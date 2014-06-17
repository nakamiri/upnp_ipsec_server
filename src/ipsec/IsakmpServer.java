package ipsec;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import encrypt.BinaryHexConverter;
import encrypt.EncryptManager;
import encrypt.KeyManager;

public class IsakmpServer {
	
	private int exit_code = -1;
	
	private long start_time = 0;

	public static String msg = "123456789";

	private DatagramSocket sock;
	private SocketAddress src_addr;
	private KeyManager key_manager;
	private EncryptManager decode;
	private EncryptManager encode;

	private NoncePayload quick_init_nonce;

	private int port = 500;

	public IsakmpServer () {

	}

	public IsakmpServer (int port) {
		this.port = port;
	}

	public void run() {
		try {
			sock = new DatagramSocket(port);

			/*
			 * 2番目
			 * 鍵交換
			 */
			// 2-1
			System.out.println("\n**** Exchange Keys ****\n");
			byte[] buf2 = new byte[1024];
			DatagramPacket pkt2 = new DatagramPacket(buf2, buf2.length);
			sock.receive(pkt2);
			
			start_time = System.currentTimeMillis();
			
			System.out.println("\nreceived from "+pkt2.getAddress()+":"+pkt2.getPort()+"\n");
			src_addr = pkt2.getSocketAddress();

			// エラーチェック
			if (checkMessage(buf2)) {
				return;
			}

			IsakmpHeader key_data = new IsakmpHeader(buf2);

			// 2-2
			sendKeyPkt(pkt2, sock, key_data);

			/*
			 * 3番目
			 * 暗号化済みIDとハッシュ
			 */
			System.out.println("\n**** Exchange ID ****\n");
			byte[] buf3 = new byte[1024];
			DatagramPacket pkt3 = new DatagramPacket(buf3, buf3.length);
			sock.receive(pkt3);
			System.out.println("\nreceived from "+pkt3.getAddress()+":"+pkt3.getPort()+"\n");

			// エラーチェック
			if (checkMessage(buf3)) {
				return;
			}

			IsakmpHeader encrypt_id = new IsakmpHeader(buf3, key_manager, decode);

			// 3-2
			sendIdParamPkt();


			/* Quick-Mode */
			
			// 3. Final
			byte[] buf5 = new byte[1024];
			DatagramPacket pkt5 = new DatagramPacket(buf5, buf5.length);
			sock.receive(pkt5);
			System.out.println("\nreceived from "+pkt5.getAddress()+":"+pkt5.getPort()+"\n");

			// エラーチェック
			if (checkMessage(buf5)) {
				return;
			}

			IsakmpHeader quick_final = new IsakmpHeader(buf5, key_manager, decode);

			exit_code = 0;
		} catch (Exception e) {

			try {
				DatagramPacket err = new DatagramPacket(msg.getBytes(), msg.getBytes().length, src_addr);
				sock.send(err);
			} catch (SocketException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} finally {
			sock.close();
		}
	}

	private void sendQuickSa () throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeyException {
		System.out.println("\n" +
				"*-*-*-*-*-*-*-*-*-*-*-*-*-*\n" +
				"----- send Quick-mode SA pkt -----\n" +
				"*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");

		// ISAKMP
		IsakmpHeader ih = new IsakmpHeader();
		ih.initSrvEncryptPkt(key_manager.getInit_cookie(), key_manager.getResp_cookie());
		ih.setNext_payload(Payload.HASH_PAYLOAD);
		ih.setExchange_type(32);

		// Hash Payload
		HashPayload hp = new HashPayload();
		hp.setNext_payload(Payload.SA_PAYLOAD);

		// SA Payload
		SaPayload sp = new SaPayload();
		sp.setNext_payload((short) Payload.NONCE_PAYLOAD);
		sp.setSituation(SaPayload.SIT_IDENTITY_ONLY);

		// Proposal Paylaod
		PropPayload pp = new PropPayload();

		// Transform Payload #1
		TransformPayload tp1 = new TransformPayload();
		tp1.setNext_payload((short) Payload.TRANSFORM_PAYLOAD);
		tp1.initSrvIpsecSa1();

		// Transform Payload #2
		TransformPayload tp2 = new TransformPayload();
		tp2.setNext_payload((short) Payload.NONE);
		tp2.initSrvIpsecSa2();

		pp.addTransformPayload(tp1);
		pp.addTransformPayload(tp2);

		sp.setPropPayloadHeader(pp);

		// Nonce Payload
		NoncePayload np = new NoncePayload();
		np.setNext_payload(Payload.ID_PAYLOAD);

		// ID Payload #1
		IdPayload ip1 = new IdPayload();
		ip1.setNext_payload(Payload.ID_PAYLOAD);

		// ID Payload #2
		IdPayload ip2 = new IdPayload();
		ip2.setNext_payload(Payload.NONE);

		/* Calc Hash */
		int length = sp.getPayload_length() + pp.getPayload_length() + np.getPayload_length() + 
				ip1.getPayload_length() + ip2.getPayload_length();
		ByteBuffer bw = ByteBuffer.allocate(length);

		bw.put(sp.getByteArray());
		bw.put(pp.getByteArray());
		bw.put(tp1.getByteArray());
		bw.put(tp2.getByteArray());
		bw.put(np.getByteArray());
		bw.put(ip1.getByteArray());
		bw.put(ip2.getByteArray());

		hp.calcQuickHashValue(bw.array(), key_manager, quick_init_nonce.getData(), null, ih.getMessage_id(), HashPayload.QUICK_HASH_2);

		// ペイロードの暗号化
		length += hp.getPayload_length();
		bw = ByteBuffer.allocate(length);

		bw.put(hp.getByteArray());
		bw.put(sp.getByteArray());
		bw.put(pp.getByteArray());
		bw.put(tp1.getByteArray());
		bw.put(tp2.getByteArray());
		bw.put(np.getByteArray());
		bw.put(ip1.getByteArray());
		bw.put(ip2.getByteArray());

		byte[] encrypted_pyld = encode.encode(bw.array());
		ih.setMessage_length(IsakmpHeader.HEADER_SIZE + encrypted_pyld.length);

		bw = ByteBuffer.allocate(ih.getMessage_length());
		bw.put(ih.getByteArray());
		bw.put(encrypted_pyld);

		byte[] decoded_pyld = encode.decode(encrypted_pyld);

		ByteBuffer dec = ByteBuffer.allocate(ih.getMessage_length() + decoded_pyld.length);
		dec.put(ih.getByteArray());
		dec.put(decoded_pyld);

		new IsakmpHeader(dec.array());

		DatagramPacket pkt = new DatagramPacket(bw.array(), bw.array().length, src_addr);
		sock.send(pkt);
	}

	private void saveByteStream(byte[] data) {
		try {
			FileOutputStream fos = new FileOutputStream("C:/Users/Nakamiri/Java_project/ipsec_dev/hoge.txt");
			fos.write(data);
			fos.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private byte[] readByteStream(String path) {
		try {
			FileInputStream fis = new FileInputStream(path);

			byte[] b = new
					byte[1024];
			fis.read(b);

			return b;
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	private void sendIdParamPkt () throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		System.out.println("\n" +
				"*-*-*-*-*-*-*-*-*-*-*-*-*-*\n" +
				"----- send ID param pkt -----\n" +
				"*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");

		// ISAKMP Header
		IsakmpHeader ih = new IsakmpHeader();
		ih.initSrvEncryptPkt(key_manager.getInit_cookie(), key_manager.getResp_cookie());

		// ID Payload
		IdPayload ip = new IdPayload();

		// Hash Payload
		HashPayload hp = new HashPayload();

		byte[] ip_byte = ip.getByteArray();

		// ハッシュの計算
		ByteBuffer bw = ByteBuffer.allocate(ih.getMessage_length() + ip.getPayload_length());
		bw.put(ip_byte);
		byte[] id_pyld = new byte[ip_byte.length - 4];
		bw.rewind();
		bw.get(new byte[4]);
		bw.get(id_pyld);

		hp.calcMainHashValue(id_pyld, key_manager, HashPayload.INIT_HASH);

		byte[] hp_byte = hp.getByteArray();

		// ペイロードの暗号化をしてパケット生成
		bw = ByteBuffer.allocate(ip.getPayload_length() + hp.getPayload_length());
		bw.put(ip_byte);
		bw.put(hp_byte);
		try {
			this.finalize();
		} catch (Throwable e) {
			// TODO 自動生成された catch ブロック
			e.printStackTrace();
		}

		encode = new EncryptManager(key_manager.getSkeyid_e());
		//		byte[] encrypted_pyld = EncryptManager.encode(bw.array(), key_manager.getSkeyid_e(), key_manager.getNonce_init());
		byte[] encrypted_pyld = encode.init_encode(bw.array(), key_manager.getSkeyid_e(), key_manager.getNonce_init());

		ih.setMessage_length(IsakmpHeader.HEADER_SIZE + encrypted_pyld.length);		
		byte[] ih_byte = ih.getByteArray();

		bw = ByteBuffer.allocate(ih.getMessage_length());
		bw.put(ih_byte);
		bw.put(encrypted_pyld);

		//		byte[] decode_pyld = EncryptManager.init_decode(encrypted_pyld, key_manager.getSkeyid_e(), key_manager.getNonce_init());
		byte[] decode_pyld = encode.decode(encrypted_pyld);

		ByteBuffer dec = ByteBuffer.allocate(ih.getMessage_length() + decode_pyld.length);
		dec.put(ih_byte);
		dec.put(decode_pyld);

		new IsakmpHeader(dec.array());

		DatagramPacket send_pkt = new DatagramPacket(bw.array(), bw.array().length, src_addr);
		sock.send(send_pkt);
	}

	private void sendKeyPkt (DatagramPacket pkt, DatagramSocket socket, IsakmpHeader receiveHeader) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException, IOException, InvalidKeyException, NoSuchPaddingException {
		System.out.println("\n" +
				"*-*-*-*-*-*-*-*-*-*-*-*-*-*\n" +
				"----- send key pkt -----\n" +
				"*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");

		// ISAKMP Header
		IsakmpHeader ih = new IsakmpHeader();
		ih.initSrvSaPkt(receiveHeader, receiveHeader.getResp_cookie());
		ih.setNext_payload(Payload.KEY_EXCHANGE_PAYLOAD);

		// KeyExchange Payload
		KeyExchangePayload kep = new KeyExchangePayload();
		kep.setNext_payload(Payload.NONCE_PAYLOAD);

		// Nonce Payload
		NoncePayload np = new NoncePayload();
		np.setNext_payload(Payload.NAT_DISCOVERY_PAYLOAD);
		//		np.setData(kep.getRandom().toByteArray());

		// Remote NAT-D Payload
		NatDiscoveryPayload remote_ndp = new NatDiscoveryPayload(pkt, receiveHeader);
		remote_ndp.setNext_payload(Payload.NAT_DISCOVERY_PAYLOAD);

		// Local NAT-D Payload
		NatDiscoveryPayload local_ndp = new NatDiscoveryPayload(socket, receiveHeader);
		local_ndp.setNext_payload(Payload.NONE);

		byte[] kep_byte = kep.getByteArray();
		byte[] np_byte = np.getByteArray();
		byte[] remote_ndp_byte = remote_ndp.getByteArray();
		byte[] local_ndp_byte = local_ndp.getByteArray();

		int isakmp_length = IsakmpHeader.HEADER_SIZE + kep.getPayload_length() + np.getPayload_length() + remote_ndp.getPayload_length() + local_ndp.getPayload_length();
		ih.setMessage_length(isakmp_length);

		byte[] ih_byte = ih.getByteArray();

		ByteBuffer bw = ByteBuffer.allocate(ih.getMessage_length());
		bw.put(ih_byte);
		bw.put(kep_byte);
		bw.put(np_byte);
		bw.put(remote_ndp_byte);
		bw.put(local_ndp_byte);

		// パケット確認
		new IsakmpHeader(bw.array());

		DatagramPacket send_pkt = new DatagramPacket(bw.array(), bw.array().length, src_addr);
		sock.send(send_pkt);

		Vector<Payload> nonce = receiveHeader.getPayload(Payload.NONCE_PAYLOAD);
		byte[] nonce_init = ((NoncePayload) nonce.firstElement()).getData();

		byte[] shared_key = kep.calcShareKey(receiveHeader.getKey_payload().getData());
		key_manager = new KeyManager(shared_key, nonce_init, np.getData(), receiveHeader.getInit_cookie(), receiveHeader.getResp_cookie());
		decode = new EncryptManager(key_manager.getSkeyid_e());
		decode.init_decode(key_manager.getNonce_resp());
	}

	private void sendSaParamPkt(IsakmpHeader receiveHeader, byte[] res_cookie) throws IOException {
		System.out.println("\n" +
				"*-*-*-*-*-*-*-*-*-*-*-*-*-*\n" +
				"----- send SA Parameter pkt -----\n" +
				"*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");

		// ISAKMP Header
		IsakmpHeader ih = new IsakmpHeader();
		ih.initSrvSaPkt(receiveHeader, res_cookie);

		// SaPayload
		SaPayload sph = new SaPayload();
		sph.initSrvSaPkt();

		// Proposal Payload
		PropPayload pph = new PropPayload();
		pph.initSrvSaPkt();

		// Transform Payload
		TypeValue[] value = new TypeValue[2];
		value[0] = new TypeValue(TransformPayload.TYPE_ENCRYPT_ALGORITHM, SaProperty.ENCRYPT_AES_CBC);
		value[1] = new TypeValue(TransformPayload.TYPE_OAKLEY_GROUP, SaProperty.GROUP_MODP_2048_BIT);

		TransformPayload tp = receiveHeader.getTransformPayload(value);

		tp.setNext_payload((short) 0);

		// VendorID Payload
		VendorIdPayload vip = new VendorIdPayload();
		vip.setNext_payload(0);
		vip.setVendor_id(BinaryHexConverter.HexStringToBytes(VendorIdPayload.NAT_TRAVERSAL));

		// set values
		pph.addTransformPayload(tp);
		sph.setPropPayloadHeader(pph);
		ih.setPayload(sph, vip);

		byte[] ih_byte = ih.getByteArray();
		byte[] sph_byte = sph.getByteArray();
		byte[] pph_byte = pph.getByteArray();
		byte[] tp_byte = tp.getByteArray();
		byte[] vip_byte = vip.getByteArray();

		// 送信バイト確認
		IsakmpHeader.outputIsakmpHeader(ih_byte);
		SaPayload.outputSaPayload(sph_byte);
		PropPayload.outputPropPayload(pph_byte);
		TransformPayload.outputTransformPayload(tp_byte);
		VendorIdPayload.outputVendorIdPayload(vip_byte);

		byte[] send_byte = new byte[ih.getMessage_length()];
		ByteBuffer bw = ByteBuffer.wrap(send_byte);
		bw.put(ih_byte);
		bw.put(sph_byte);
		bw.put(pph_byte);
		bw.put(tp_byte);
		bw.put(vip_byte);

		DatagramPacket pkt = new DatagramPacket(send_byte, send_byte.length, src_addr);
		sock.send(pkt);
	}

	private boolean checkMessage (byte[] buf) {
		ByteBuffer bw = ByteBuffer.wrap(buf);

		byte[] chk = new byte[msg.getBytes().length];
		bw.get(chk);

		String chk_str = new String(chk);

		return chk_str.equals(msg);
	}

	public int getExit_code() {
		return exit_code;
	}

	public long getStart_time() {
		return start_time;
	}

}
