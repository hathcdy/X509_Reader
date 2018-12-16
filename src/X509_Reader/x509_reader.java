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
			//��ȡ֤���ļ�		
			File file = new File("./bilibili.cer");
			InputStream inStream = new FileInputStream(file);
			//����X509������
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			//����֤�����
			X509Certificate oCert = (X509Certificate)cf.generateCertificate(inStream);
			inStream.close();
			SimpleDateFormat dateformat = new SimpleDateFormat("yyyy/MM/dd"); 
			String info = null;
			//֤��汾
			info = String.valueOf(oCert.getVersion());
			System.out.println("֤��汾:" + info);
			//֤�����к�
			info = oCert.getSerialNumber().toString(16);
			System.out.println("֤�����к�:" + info);
			//�㷨OID
			info = oCert.getSigAlgOID();
			System.out.println("֤���㷨OID:" + info);
			//֤��䷢��
			info = oCert.getIssuerDN().getName();
			System.out.println("֤��䷢��:" + info); 
			//֤������
			info = oCert.getSubjectDN().getName();
			System.out.println("֤��ӵ����:" + info);
			//֤����Ч��
			//֤����Ч����
			Date beforedate = oCert.getNotBefore();
			info = dateformat.format(beforedate);
			System.out.println("֤����Ч����:" + info);
			//֤��ʧЧ����
			Date afterdate = oCert.getNotAfter();
			info = dateformat.format(afterdate);
			System.out.println("֤��ʧЧ����:" + info);			
			//֤��ǩ���㷨
			info = oCert.getSigAlgName();
			System.out.println("֤��ǩ���㷨:" + info);
			byte [] sig = oCert.getSignature();
			//ǩ��
			System.out.println("ǩ��:" + sig);
			//��Կ
		    PublicKey pk = oCert.getPublicKey();
		    String publicKeyAlgorithm = pk.getAlgorithm();
		    System.out.println("��Կ�㷨:" + publicKeyAlgorithm);		        
		    byte [] pkenc = pk.getEncoded();  
		    System.out.print("��Կ:");
		    for(int i = 0;i < pkenc.length; i++) System.out.print(pkenc[i] + ",");
		    System.out.println();
		    
		    boolean[] issuerUniqueID = oCert.getIssuerUniqueID();
		    boolean[] subjectUniqueID = oCert.getSubjectUniqueID();
		    //֤����չ��Ϣ
		    Object[] extOID1 = oCert.getCriticalExtensionOIDs().toArray();
		    Object[] extOID2 = oCert.getNonCriticalExtensionOIDs().toArray();
		}
		catch (Exception e) 
		{  
			e.printStackTrace();
			System.out.println("����֤�����");
		}
	}//end showCertInfo
 
	public static void main(String[] args) {
		showCertInfo();
	}
}
