def get_script():
    # Este script en Frida enumerará las clases cargadas (Android ejemplo)
    return """
        Java.perform(function() {
            console.log("Enumerando clases cargadas...");
            
            // Obtener todas las clases cargadas en el proceso
            var classes = Java.enumerateLoadedClassesSync();
            
            // Mostrar las clases en la consola
            for (var i = 0; i < classes.length; i++) {
                //console.log(classes[i]);
                send({ action: 'log', message: 'Clase cargada: ' + classes[i] });
            }
            
            console.log("Total de clases enumeradas: " + classes.length);
        });

    """