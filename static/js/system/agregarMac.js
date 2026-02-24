var inicializarControles=function()
	{
        $("#mensaje").hide();
//Submit form
	$("#guardar").click(function(e){
        
        e.preventDefault();
        if($("#mac").val().length==0){
                console.log("falta mac ");
                return false;
        }
        
		if ($("#nombre").val().length==0){
            console.log("falta nombre ");
            return false;
        }
		
        
        
        $("#guardar").attr("disabled", "disabled");		
		//Add preloader
		if (!$(".form-submit").find("img.preloader").length) {
			$("#submit").after('<img src="images/preloader.gif" class="preloader" />');
		}
		
		//Post form
		//$(".notification").fadeOut(300, function() {
			$.post("agregarMac.php",
                   {
				name: 		$("#nombre").val(),
				mac: 		$("#mac").val()										
			},
				function(data) {
					//Show notification
					respuesta = JSON.parse(data);
                    if(respuesta[0]){
                        $("#mensaje").text("Agregado con exito "+respuesta[1]);                        
                        $("#mensaje").removeClass("alert-danger");
                        $("#mensaje").addClass("alert-success");
                        $("#mensaje").show();
                    }else{
                        $("#mensaje").text("Ocurrio el error: "+respuesta[1]);                        
                        $("#mensaje").removeClass("alert-success");
                        $("#mensaje").addClass("alert-danger");
                        $("#mensaje").show();
                    }
                    console.log(respuesta);
				}
			);
		//});
		
		return false;
	});
    }
 $(document).ready(function(){inicializarControles()});