# Proyecto de Cifrado de Exámenes

## Descripción

El propósito de este proyecto es simular una herramienta para empaquetar y distribuir exámenes de manera segura y confiable. La entrega del examen solo se realiza después de que una entidad de sellado verifique la identidad del alumno y asigne la fecha de realización del examen. El proceso consta de tres pasos principales:

1. **Creación del Examen Empaquetado**: Incluye datos del examen cifrados, una clave secreta y la firma del alumno.
2. **Verificación y Sellado**: La entidad de sellado verifica la identidad del alumno y asigna una fecha de entrega, sellando el examen.
3. **Desempaquetado**: La información del examen se recupera solo si el sello de la entidad de sellado es válido.

## Estrategias Empleadas

- **Cifrado**: Se utiliza cifrado DES de 56 bits para garantizar la confidencialidad del contenido del examen.
- **Firma Digital**: Para verificar la identidad del alumno, se usa una firma digital basada en RSA.
- **Sellado**: La autoridad de sellado verifica la firma y determina el firmante, asegurando la integridad y autenticidad del examen.

## Paquete Resultante

El paquete final incluye los siguientes componentes:

1. Examen cifrado.
2. Clave secreta cifrada.
3. Firma del alumno.
4. Fecha de sellado y verificación de los datos.
5. Firma de la autoridad de sellado.

## Estructura del Proyecto

El proyecto está compuesto por varias clases y métodos esenciales:

- `Paquete`
- `GenerarClaves`
- `EmpaquetarExamen`
- `SellarExamen`
- `DesempaquetarExamen`


