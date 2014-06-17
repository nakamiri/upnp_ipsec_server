/*
 * ByteArrayBits.java
 *
 * Copyright (C) 1999 FreeBeans <freebeans@mub.biglobe.ne.jp>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Copyright (C) 1999年 FreeBeans <freebeans@mub.biglobe.ne.jp>
 *
 * 本プログラムはフリー・ソフトウェアです。あなたは、Free Software Foundation 
 * が公表したGNU 一般公有使用許諾の「バージョン２」或いはそれ以降の各バージョ
 * ンの中からいずれかを選択し、そのバージョンが定める条項に従って本プログラム
 * を再頒布または変更することができます。
 * 本プログラムは有用とは思いますが、頒布にあたっては、市場性及び特定目的適合
 * 性についての暗黙の保証を含めて、いかなる保証も行ないません。詳細については
 * GNU 一般公有使用許諾書をお読みください。
 *
 * あなたは、本プログラムと一緒にGNU 一般公有使用許諾の写しを受け取ってい
 * るはずです。そうでない場合は、Free Software Foundation, Inc., 675 Mass Ave,
 * Cambridge, MA 02139, USA へ手紙を書いてください。
 */

package encrypt;

import java.io.Serializable;

/**
 * バイト配列から任意のビットを取り出す事を可能にするクラス.
 * あるバイト配列 data[] 内の各ビットは、以下のような順番で並んでいるとみなされる.
 * <br>data[0] の 7bit 目
 * <br>data[0] の 6bit 目
 * <br>...
 * <br>data[0] の 0bit 目
 * <br>data[1] の 7bit 目
 * <br>...
 * <br>data[n] の 0bit 目
 *
 */
public class ByteArrayBits implements Serializable, Cloneable {
	
	/**
	 * データ本体.
	 */
	private byte[] data;
	
	/**
	 * 指定されたデータからビットを抽出する BitArrayBits のインスタンスを作成する.
	 * データ本体のコピーは行わないので、呼出元はこのデータの内容を直接変更してはいけない.
	 *
	 * @param	data	抽出対象となるデータ.
	 * @throws	java.lang.NullPointerException	dataがnullの場合.
	 */
	public ByteArrayBits(byte[] data) {
		if (data == null) {
			throw new NullPointerException();
		}
		this.data = data;
	}
	
	/**
	 * 指定されたビット数だけビットの先頭から取り出し、int で返す.
	 * 32ビット以上のデータを取り出す事は出来ない.
	 *
	 * @param	startbit	ビット抽出開始位置.
	 * @param	endbit		ビット抽出終了位置.
	 * @return	下位ビットに取り出した内容が格納された32ビット値.
	 *
	 * @throws	java.lang.IllegalArgumentException	endbit - startbit が 32 を超えていた場合.
	 * @throws	java.lang.IndexOutOfBoundsException	配列の範囲を超えていた場合.
	 *
	 */
	public int subbits(int startbit, int endbit) {
		if ((endbit - startbit) > 32) {
			throw new IllegalArgumentException();
		}
		int ret = 0;
		for (int i = startbit; i < endbit; ++i) {
			ret <<= 1;
			int arrayindex = i / 8;
			int bitoffset  = i % 8;
			ret |= (((1 << (7 - bitoffset)) & data[arrayindex]) >> (7 - bitoffset));
		}
		return ret;
	}
	
	/**
	 * 全体のビット長を返す.
	 *
	 * @return	全体のビット長.
	 */
	public int getBitLength() {
		return data.length * 8;
	}
	 
	/**
	 * このオブジェクトのコピーを作成する.
	 * （データの内容もコピーされる）
	 *
	 * @return	このオブジェクトのコピー.
	 */
	public Object clone() {
		try {
			ByteArrayBits bits = (ByteArrayBits) super.clone();
			bits.data = new byte[data.length];
			System.arraycopy(data, 0, bits.data, 0, bits.data.length);
			return bits;
		} catch (CloneNotSupportedException cnse) {
			throw new Error();
		}
	}
}
