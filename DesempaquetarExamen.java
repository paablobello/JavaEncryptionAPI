import java.io.*;

import java.nio.file.Files;
import java.nio.file.Paths;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class DesempaquetarExamen {
    
    public static void main(String[] args) {
        String pathPaquete = args[0];
        String pathExamen = args[1];
        String pathKUAlumno = args[2];
        String pathKRProfesor = args[3];

        Security.addProvider(new BouncyCastleProvider());

        try{
            KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
            PublicKey KUAlumno = recuperarKUAlumno(pathKUAlumno, keyFactoryRSA);
            PrivateKey KRProfesor = recuperarKRProfesor(pathKRProfesor, keyFactoryRSA);

            Paquete paqueteLeido = new Paquete(pathPaquete);
            byte[] examenCifrado = paqueteLeido.getContenidoBloque("Examen cifrado");
            byte[] claveSecretaCifrada = paqueteLeido.getContenidoBloque("Clave secreta cifrada");
            byte[] firmaAlumnoBytes = paqueteLeido.getContenidoBloque("Firma del alumno");
            byte[] fechaFirma = paqueteLeido.getContenidoBloque("Datos Autoridad");
            byte[] firmaAutoridad = paqueteLeido.getContenidoBloque("Firma Autoridad");

            SecretKey claveSecreta = descifrarClaveSecreta(KRProfesor, claveSecretaCifrada);
            System.out.println("clave secreta descifrada correctamente");
            String examen = descifrarExamen(examenCifrado, claveSecreta);
            System.out.println("examen descifrado correctamente");
            //String firmaAlumno = descifrarFirmaAlumno(KUAlumno, firmaAlumnoBytes);

            System.out.println("Firma de la autoridad: " + firmaAutoridad.toString());

            guardarExamen(examen, pathExamen);
            System.out.println("examen en claro guardado: ");
            System.out.println(examen);


        } catch(NoSuchAlgorithmException e){
            System.err.println("No se encuentra el algoritmo");
        } catch(NoSuchProviderException e){
            System.err.println("No se encuentra el provider");
        } catch(Exception e){
            e.printStackTrace();
        }
    }

    public static PublicKey recuperarKUAlumno(String KU, KeyFactory keyFactoryRSA) throws NoSuchProviderException, Exception {
        byte[] buffer = Files.readAllBytes(Paths.get(KU));

        X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(buffer);
		PublicKey KUAlumno = keyFactoryRSA.generatePublic(clavePublicaSpec);

        return KUAlumno;
    }

    public static PrivateKey recuperarKRProfesor(String KR, KeyFactory keyFactoryRSA) throws NoSuchProviderException, Exception {
        byte[] buffer = Files.readAllBytes(Paths.get(KR));

        PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(buffer);
		PrivateKey KRProfesor = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

        return KRProfesor;
    }

    public static SecretKey descifrarClaveSecreta(PrivateKey KR, byte[] claveSecretaCifrada) throws Exception {
        System.out.println("--Descifrando clave secreta--");

        Cipher cifrador = Cipher.getInstance("RSA", "BC");
        cifrador.init(Cipher.DECRYPT_MODE, KR);

        byte[] claveSecretaByte = cifrador.doFinal(claveSecretaCifrada);
        SecretKey claveSecreta = new SecretKeySpec(claveSecretaByte, 0, claveSecretaByte.length, "RSA");

        return claveSecreta;
    }

    public static String descifrarExamen(byte[] examenCifrado, SecretKey claveSecreta) throws NoSuchAlgorithmException, Exception {
        System.out.println("--Descifrando examen--");

        Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding","BC");
        cifrador.init(Cipher.DECRYPT_MODE, claveSecreta);

        String examen = new String(cifrador.doFinal(examenCifrado));

        return examen;
    }

    public static String descifrarFirmaAlumno(PublicKey KUAlumno, byte[] firmaAlumnoBytes) throws Exception {
        System.out.println("--Descifrando firma del alumno--");

        Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding","BC");
        cifrador.init(Cipher.DECRYPT_MODE, KUAlumno);

        String firma = new String(cifrador.doFinal(firmaAlumnoBytes));

        return firma;
    }

    public static void guardarExamen(String examen, String pathExamen) throws Exception {
        System.out.println("--Guardando el examen en texto claro--");

        byte[] examenDescifrado = examen.getBytes();
        FileOutputStream examenGuardado = new FileOutputStream(pathExamen + ".txt");
        examenGuardado.write(examenDescifrado);
        examenGuardado.close();
    }


}