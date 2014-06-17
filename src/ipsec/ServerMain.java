package ipsec;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.Vector;


public class ServerMain {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Vector<Integer> time = new Vector<Integer>();
		
		try {
			BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			System.out.print("input port number:");
			int port = Integer.parseInt(br.readLine());

			for (int i = 0; i < 100; i++) {
				System.out.println("-*-*-*-* loop " + i + " *-*-*-*-");
				
				IsakmpServer isakmp = new IsakmpServer(port);
				isakmp.run();

				long start = isakmp.getStart_time();
				
				long stop = System.currentTimeMillis();
				
				if (isakmp.getExit_code() == 0) {
					time.add((int) (stop - start));
					System.out.println("Estimate time: " + (stop- start));
				}
			}
		} catch (IOException e) {
			// TODO 自動生成された catch ブロック
			e.printStackTrace();
		}
		
		try {
			PrintWriter pw = new PrintWriter("./upnptime.txt");
			pw.println("Exec num: " + time.size());
			for (int i = 0; i < time.size(); i++) {
				pw.println(time.get(i));
			}
			pw.close();
			
			System.out.println(new File("./upnptime.txt").getAbsolutePath());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
