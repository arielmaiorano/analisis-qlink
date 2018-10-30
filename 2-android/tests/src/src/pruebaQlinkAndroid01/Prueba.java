package pruebaQlinkAndroid01;


import java.util.Date;

import javax.crypto.SecretKey;


public class Prueba {

	static final String salt = "2f3a3d27";
	static final String iv = "b9d2536eef0aec8f706d4292cf386d8e";
	static final String ciphertext = "Nnhw6jYYRJmzBmiVsfiNSQ==\n";
	static final long randomHash = 1515636395425L;

	static final int claroFixLen = 2;
	static final int passwordFixLenMin = 19;
	static final int passwordFixLenMax = 19;
	
	static DecryptThread[] dths = new DecryptThread[64];
	
	public static void main(String[] args) {

		for (int i=0; i<dths.length; i++)	{
			dths[i] = new DecryptThread("DecryptThread #" + i);
			dths[i].start();
		}
		
		long ts_stats = new Date().getTime();
		System.out.println("iniciando programa...");
		long cant_pruebas = 0;
		String passphrase_test;
		update_fechas();
		while (_fechas != null)	{
			passphrase_test = "";
			for (int i = 0; i < _fechas.length; i++)	{
				passphrase_test = generateRandomString(String.valueOf(_fechas[i]) + passphrase_test);
				passphrase_test = Base64.encodeToString(passphrase_test.getBytes(), Base64.DEFAULT).substring(0, 32);
			}
			cant_pruebas++;
			if (cant_pruebas % 10000 == 0)	{
				long tmp = new Date().getTime();
				System.out.println("cantidad de pruebas: " + cant_pruebas + " / " + _fechas_total + " - " + (tmp - ts_stats) + " ms");
				ts_stats = tmp;
			}
			outerloop:
			while (_fechas != null)	{
				for (int i=0; i<dths.length; i++)	{
					if (! dths[i].decrypting())	{
						dths[i].decrypt(passphrase_test);
						break outerloop;
					}
				}
				try {
					Thread.sleep(1);
				} catch (InterruptedException e) {
				}
			}
			update_fechas();
		}
		System.out.println("programa finalizado.");
	}

	static int _fechas_len = 0;
	static long[] _fechas = null;
	static int[] _deltas = null;
	static int[] _deltas_min = null;
	static int[] _deltas_max = null;
	static long _fechas_total = 1;
	private static void update_fechas() {

		if (_fechas == null)	{

			_fechas_len = (claroFixLen * 3) + 3;
			_fechas = new long[_fechas_len];
			_deltas = new int[_fechas_len];
			_deltas_min = new int[_fechas_len];
			_deltas_max = new int[_fechas_len];
			
			_deltas_min[_fechas_len - 1] = 105;//109;
			_deltas_max[_fechas_len - 1] = 114;

			_deltas_min[_fechas_len - 2] = 1631;//1636;
			_deltas_max[_fechas_len - 2] = 1640;
			
			for (int i = 0; i < _fechas_len - 3; i += 3)	{

				_deltas_min[_fechas_len - 3 - i] = 391;//392,520
				_deltas_max[_fechas_len - 3 - i] = 520;

				_deltas_min[_fechas_len - 4 - i] = 75; //77,75
				_deltas_max[_fechas_len - 4 - i] = 77;
				
				_deltas_min[_fechas_len - 5 - i] = 2;//2,2
				_deltas_max[_fechas_len - 5 - i] = 2;
			}			
			
			_deltas_min[0] = 401;//404
			_deltas_max[0] = 410;
			
			for (int i = 0; i < _fechas_len; i++)	{
				_deltas[i] = _deltas_min[i];
				_fechas_total *= (_deltas_max[i] - _deltas_min[i]) + 1;
			}
		}
		
		int i = _fechas_len - 1;
		while (true)	{
			if (_deltas[i] + 1 > _deltas_max[i])	{
				_deltas[i] = _deltas_min[i];
				i--;
				if (i < 0)	{
					_fechas = null;
					return;
				}
			} else	{
				_deltas[i]++;
				break;
			}
		}
		_fechas[_fechas_len - 1] = randomHash - _deltas[_fechas_len - 1];
		for (i = 1; i < _fechas_len; i++)	{
			_fechas[_fechas_len - 1 - i] = _fechas[_fechas_len - i] - _deltas[_fechas_len - 1 - i];
		}
	}
	
	// recorte/adaptación de orgiinal en QlinkActivity.java
	static final String characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	private static String generateRandomString(String seeded) {
	    String randomString = "";
		byte[] bytes = InsecureSHA1PRNGKeyDerivator.deriveInsecureKey(seeded.getBytes(), 128);
		int bytes_idx = 0;
	    int bits, val;
	    for (int i = 0; i < 32; i++)	{
	    	bits = 0;
			for (int j = 0; j < 4; j++)	{
				bits = (bits << 8) + (bytes[bytes_idx + j] & 0xFF);
			}
			bytes_idx += 4;
			bits = bits >>> 1;
	        val = bits % 61;
		    randomString = randomString + characters.charAt(val);
	    }
	    return randomString;
	}
	
}

class DecryptThread extends Thread {
	
	private String passphrase = null;
	private AesUtil aesUtil;
	
    public DecryptThread(String str) {
        super(str);
        aesUtil = new AesUtil(256, 100);
    }
    
    public void run() {
        try {
	    	while (true)	{
	    		if (passphrase != null)	{
	    			for (int i=Prueba.passwordFixLenMin; i<=Prueba.passwordFixLenMax; i++)	{
    					if (aesUtil.decrypt(Prueba.salt, Prueba.iv, passphrase.substring(0, i), Prueba.ciphertext).startsWith("%%A%%"))	{
							System.out.println("*** DESCIFRADO");
							System.out.println("texto en claro: " + aesUtil.decrypt(Prueba.salt, Prueba.iv, passphrase.substring(0, i), Prueba.ciphertext).replace("%%A%%", "").replace("%%C%%", ""));
							System.out.println("password para pbkdf2: " + passphrase.substring(0, i) + " (longitud = " + i + ")");
							System.exit(0);
						}
	    			}
					passphrase = null;
	    		}
                sleep(1);
	    	}
        } catch (InterruptedException e) {
        	System.out.println("thread " + getName() + " interrumpido.");
        	return;
		}        
    }
    
    public boolean decrypting()	{
    	return(passphrase != null);
    }
    
    public void decrypt(String tmp)	{
    	passphrase = tmp;
    }
}
