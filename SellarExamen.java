import java.io.*;

import java.nio.file.Files;
import java.nio.file.Paths;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;
import javax.crypto.SecretKey;

import java.util.Base64;
import java.util.Calendar;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class SellarExamen {
    private static byte[] datos_fichero;
    private static String fechaFirma;
    private static KeyFactory keyFactoryRSA;
    private static SecretKey clave_secreta;
    private static int hora, minutos, segundos;
 
    public static void main(String[] args) throws Exception {
        String pathPaquete = args[0];
        String pathKRAutoridad = args[1];
        String pathKUAlumno = args[2];
        
        Paquete paquetito = new Paquete(pathPaquete);
        Calendar calendario = Calendar.getInstance();
        fechaFirma = calendario.getTime().toString() + " Firmado por la autoridad de sellado";
        
        Security.addProvider(new BouncyCastleProvider());
        
        try{
            byte[] bytesAutoridad = fechaFirma.getBytes();
            byte[] bloqueDatosExamen = paquetito.getContenidoBloque("Examen cifrado");
            byte[] bloqueClaveSecreta = paquetito.getContenidoBloque("Clave secreta cifrada");
            byte[] bloqueFirmaAlumno = paquetito.getContenidoBloque("Firma del alumno");
            System.out.println("--Bloques del paquete obtenidos--");

            KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
            PrivateKey autoridadKR = leerClavePrivadaAutoridad(pathKRAutoridad, keyFactoryRSA);
            PublicKey alumnoKU = leerClavePublicaAlumno(pathKUAlumno, keyFactoryRSA);
            
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(bloqueDatosExamen);
            outputStream.write(bloqueClaveSecreta);
            byte[] bloque_comprobacion = outputStream.toByteArray();
            
            Signature firmaAutoridad = firmarDatosAutoridad(autoridadKR, bloqueDatosExamen, bloqueClaveSecreta, bloqueFirmaAlumno, bytesAutoridad);
            byte[] firmaAutoridadByte = firmaAutoridad.sign();

            Signature firmaAlumno = Signature.getInstance("SHA1withRSA", "BC");
            firmaAlumno.initVerify(alumnoKU);
            firmaAlumno.update(bloqueDatosExamen);
            firmaAlumno.update(bloqueClaveSecreta);
            boolean verificadoFirmaAlumno = firmaAlumno.verify(bloqueFirmaAlumno);
            
            if(verificadoFirmaAlumno){
                System.out.println("La firma del alumno es válida\n");
                
                paquetito.anadirBloque("Firma Autoridad", firmaAutoridadByte);
                System.out.println("Bloque Datos con la fecha de la firma de la autoridad de sellado");
                paquetito.anadirBloque("Datos Autoridad", bytesAutoridad);
                System.out.println("Paquete Firmado por " + pathKRAutoridad);

                paquetito.escribirPaquete(pathPaquete);
                
                System.out.println("Fichero " + pathPaquete + " guardado con la firma de la autoridad de sellado: " + pathKRAutoridad);
            } else{
                System.out.println("La firma del alumno no es válida, no se puede firmar.\n");
            }
        } catch(Exception e){
            e.printStackTrace();
        }
    }


    public static PrivateKey leerClavePrivadaAutoridad(String fileAutoridad, KeyFactory keyFactoryRSA) throws Exception {
        byte[] bufferPriv = Files.readAllBytes(Paths.get(fileAutoridad));

        PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
        PrivateKey autoridadKR = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
        System.out.println("Clave privada autoridad sellado obtenida ");

        return autoridadKR;
    }

    public static Signature firmarDatosAutoridad(PrivateKey autoridadKR, byte[] bloqueDatosExamen, byte[] bloqueClaveSecreta, byte[] bloqueFirmaAlumno, byte[] bytesAutoridad) throws Exception {
        Signature firmaAutoridad = Signature.getInstance("SHA1withRSA", "BC");
        firmaAutoridad.initSign(autoridadKR);
        firmaAutoridad.update(bloqueDatosExamen);
        firmaAutoridad.update(bloqueClaveSecreta);
        firmaAutoridad.update(bloqueFirmaAlumno);
        firmaAutoridad.update(bytesAutoridad);
        
        return firmaAutoridad;
    }

    public static PublicKey leerClavePublicaAlumno(String fileAlumno, KeyFactory keyFactoryRSA) throws Exception {
        byte[] bufferPub = Files.readAllBytes(Paths.get(fileAlumno));

        X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
        PublicKey alumnoKU = keyFactoryRSA.generatePublic(clavePublicaSpec);
        System.out.println("Clave publica alumno obtenida");

        return alumnoKU;
    }


}