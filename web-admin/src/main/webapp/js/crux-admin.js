var configuration = {};

function loadConfiguration() {

	$.get('/setup', function(data) {
		configuration = eval("(" + data + ")");
		$("#containerId").text(configuration.containerId);
	});

}

$(document).ready(function() {
	loadConfiguration();	
});