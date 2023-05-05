var w3tcstackpath2_graph_data;

function w3tcstackpath2_load() {
	jQuery('.w3tcstackpath2_loading').removeClass('w3tc_hidden');
	jQuery('.w3tcstackpath2_content').addClass('w3tc_hidden');
	jQuery('.w3tcstackpath2_error').addClass('w3tc_none');

	jQuery.getJSON(ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
		'&w3tc_action=cdn_stackpath2_widgetdata',
		function(data) {
			if (data && data.error) {
				jQuery('.w3tcstackpath2_error').removeClass('w3tc_none');
				jQuery('.w3tcstackpath2_error_details').html(data.error);
				jQuery('.w3tcstackpath2_loading').addClass('w3tc_hidden');
				return;
			}

			for (p in data) {
				var v = data[p];
				if (p.substr(0, 4) == 'url_')
					jQuery('.w3tcstackpath2_href_' + p.substr(4)).attr('href', v);
				else
					jQuery('.w3tcstackpath2_' + p).html(v);
			}

			var chart_data = google.visualization.arrayToDataTable(data.chart_mb);

			var chart = new google.visualization.ColumnChart(
				document.getElementById('chart_div'));
			var options = {};//colors: 'blue,red'};
			chart.draw(chart_data, options);

			jQuery('.w3tcstackpath2_content').removeClass('w3tc_hidden');
			jQuery('.w3tcstackpath2_loading').addClass('w3tc_hidden');
		}
	).fail(function() {
		jQuery('.w3tcstackpath2_error').removeClass('w3tc_none');
		jQuery('.w3tcstackpath2_content').addClass('w3tc_hidden');
		jQuery('.w3tcstackpath2_loading').addClass('w3tc_hidden');
	});
}



google.load("visualization", "1", {packages:["corechart"]});
google.setOnLoadCallback(w3tcstackpath2_load);
