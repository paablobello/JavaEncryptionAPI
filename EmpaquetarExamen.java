import java.io.*;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.Charset;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class EmpaquetarExamen {

    public static void main(String[] args){

        if (args.length != 4){
        System.out.println("Numero de parametros incorrectos");
        System.exit(1);
        }

        String pathExamen = args[0];
        String pathPaquete = args[1];
        String pathKUProfesor = args[2];
        String pathKRAlumno = args[3];

        Paquete paquete = new Paquete();

        Security.addProvider(new BouncyCastleProvider());

        try{
            KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
            PublicKey KUProfesor = recuperarKUProfesor(pathKUProfesor, keyFactoryRSA);
            PrivateKey KRAlumno = recuperarKRAlumno(pathKRAlumno, keyFactoryRSA);

            SecretKey claveSecreta = generarClaveSecreta();
            System.out.println("clave secreta creada correctamente");
            byte[] examenCifrado = cifrarExamen(claveSecreta, pathExamen);
            System.out.println("examen cifrado correctamente");
            
            byte[] claveSecretaCifrada = cifrarClaveSecreta(KUProfesor, claveSecreta);
            System.out.println("clave secreta cifrada correctamente");
            Signature firmaAlumno = firmarDatosAlumno(examenCifrado, claveSecretaCifrada, KRAlumno);
            System.out.println("firma del alumno lista");

            byte[] firmaAlumnoBytes = firmaAlumno.sign();

            paquete.anadirBloque("Examen cifrado", examenCifrado);
            paquete.anadirBloque("Clave secreta cifrada", claveSecretaCifrada);
            paquete.anadirBloque("Firma del alumno", firmaAlumnoBytes);

            paquete.escribirPaquete(pathPaquete);

        } catch(NoSuchProviderException e){
            System.err.println("No se encuentra el provider");
        } catch(NoSuchAlgorithmException e){
            System.err.println("No se encuentra el algoritmo");
        } catch(Exception e){
            e.printStackTrace();
        }

    }


    public static PublicKey recuperarKUProfesor(String KU, KeyFactory keyFactoryRSA) throws NoSuchProviderException, Exception {
        byte[] buffer = Files.readAllBytes(Paths.get(KU));

        X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(buffer);
		PublicKey KUProfesor = keyFactoryRSA.generatePublic(clavePublicaSpec);

        return KUProfesor;
    }

    public static PrivateKey recuperarKRAlumno(String KR, KeyFactory keyFactoryRSA) throws NoSuchProviderException, Exception {
        byte[] buffer = Files.readAllBytes(Paths.get(KR));

        PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(buffer);
		PrivateKey KRAlumno = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

        return KRAlumno;
    }

    public static SecretKey generarClaveSecreta() throws NoSuchAlgorithmException, Exception {
        System.out.println("--Generando clave secreta--");

        KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
        generadorDES.init(56);
        SecretKey claveSecreta = generadorDES.generateKey();

        return claveSecreta;
    }

    public static byte[] cifrarExamen(SecretKey claveSecreta, String pathExamen) throws Exception {
        System.out.println("--Cifrando examen--");

        Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding","BC");
        cifrador.init(Cipher.ENCRYPT_MODE, claveSecreta);

        byte[] bufferClaro = Files.readAllBytes(Paths.get(pathExamen));
        byte[] bufferCifrado = cifrador.doFinal(bufferClaro);

        return bufferCifrado;
    }

    public static byte[] cifrarClaveSecreta(PublicKey KUProfesor, SecretKey claveSecreta) throws Exception{
        System.out.println("--Cifrando clave secreta con la clave publica del profesor--");

        Cipher cifrador = Cipher.getInstance("RSA", "BC");
        cifrador.init(Cipher.ENCRYPT_MODE, KUProfesor);
        byte[] bufferClaro = claveSecreta.getEncoded();
        byte[] bufferCifrado = cifrador.doFinal(bufferClaro);

        return bufferCifrado;
    }

    public static Signature firmarDatosAlumno(byte[] cifradoExamen, byte[] claveSecretaCifrada, PrivateKey KRAlumno) throws Exception {
        System.out.println("--Firmando los datos del alumno--");

        Signature firmaAlumno = Signature.getInstance("SHA1withRSA", "BC");
        firmaAlumno.initSign(KRAlumno);
        firmaAlumno.update(cifradoExamen);
        firmaAlumno.update(claveSecretaCifrada);

        return firmaAlumno;
    }


}