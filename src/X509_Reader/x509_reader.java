package X509_Reader;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Set;

import org.omg.CORBA.OctetSeqHolder;

import com.sun.security.auth.X500Principal;
import com.sun.xml.internal.bind.v2.schemagen.xmlschema.List;

public class x509_reader
{
	public static void showCertInfo()
	{
		try
		{
			//读取证书文件		
			File file = new File("./bilibili.cer");
			InputStream inStream = new FileInputStream(file);
			//创建X509工厂类
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			//创建证书对象
			X509Certificate oCert = (X509Certificate)cf.generateCertificate(inStream);
			inStream.close();
			SimpleDateFormat dateformat = new SimpleDateFormat("yyyy/MM/dd"); 
			String info = null;
			//证书版本
			info = String.valueOf(oCert.getVersion());
			System.out.println("证书版本:" + info);
			//证书序列号
			info = oCert.getSerialNumber().toString(16);
			System.out.println("证书序列号:" + info);
			//算法OID
			info = oCert.getSigAlgOID();
			System.out.println("证书算法OID:" + info);
			//证书颁发者
			info = oCert.getIssuerDN().getName();
			System.out.println("证书颁发者:" + info); 
			//证书主体
			info = oCert.getSubjectDN().getName();
			System.out.println("证书拥有者:" + info);
			//证书有效期
			//证书生效日期
			Date beforedate = oCert.getNotBefore();
			info = dateformat.format(beforedate);
			System.out.println("证书生效日期:" + info);
			//证书失效日期
			Date afterdate = oCert.getNotAfter();
			info = dateformat.format(afterdate);
			System.out.println("证书失效日期:" + info);			
			//证书签名算法
			info = oCert.getSigAlgName();
			System.out.println("证书签名算法:" + info);
			byte [] sig = oCert.getSignature();
			//签名
			System.out.println("签名:" + sig);
			//公钥
		    PublicKey pk = oCert.getPublicKey();
		    String publicKeyAlgorithm = pk.getAlgorithm();
		    System.out.println("公钥算法:" + publicKeyAlgorithm);		        
		    byte [] pkenc = pk.getEncoded();  
		    System.out.print("公钥:");
		    for(int i = 0;i < pkenc.length; i++) System.out.print(pkenc[i] + ",");
		    System.out.println();
		    
		    boolean[] issuerUniqueID = oCert.getIssuerUniqueID();
		    boolean[] subjectUniqueID = oCert.getSubjectUniqueID();
		    //证书扩展信息
		    Object[] extOID1 = oCert.getCriticalExtensionOIDs().toArray();
		    Object[] extOID2 = oCert.getNonCriticalExtensionOIDs().toArray();
		}
		catch (Exception e) 
		{  
			e.printStackTrace();
			System.out.println("解析证书出错！");
		}
	}//end showCertInfo
 
	public static void main(String[] args) {
		showCertInfo();
	}
}
