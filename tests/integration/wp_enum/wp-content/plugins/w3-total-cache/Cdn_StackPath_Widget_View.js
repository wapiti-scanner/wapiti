var w3tcstackpath_graph_data;

function w3tcstackpath_load() {
	jQuery('.w3tcstackpath_loading').removeClass('w3tc_hidden');
	jQuery('.w3tcstackpath_content').addClass('w3tc_hidden');
	jQuery('.w3tcstackpath_error').addClass('w3tc_none');

	jQuery.getJSON(ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
		'&w3tc_action=cdn_stackpath_widgetdata',
		function(data) {
			if (data && data.error) {
				jQuery('.w3tcstackpath_error').removeClass('w3tc_none');
				jQuery('.w3tcstackpath_error_details').html(data.error);
				jQuery('.w3tcstackpath_loading').addClass('w3tc_hidden');
				return;
			}

			for (p in data) {
				var v = data[p];
				if (p.substr(0, 4) == 'url_')
					jQuery('.w3tcstackpath_href_' + p.substr(4)).attr('href', v);
				else
					jQuery('.w3tcstackpath_' + p).html(v);
			}

			var chart_data = google.visualization.arrayToDataTable(data.graph);

			var chart = new google.visualization.PieChart(
				document.getElementById('chart_div'));
			var options = {colors: data.colors};
			chart.draw(chart_data, options);

			var popuplar_html = '';
			if ( data.popular_files && data.popular_files.length > 0 ) {
				var compare = data.popular_files[0]['hit'];
				for ( var n = 0; n < data.popular_files.length; n++) {
					var file = data.popular_files[n];
					popuplar_html += '<li>' +
						'<span style="display:inline-block; background-color: ' + file.color +
						';width: ' + (file.hit / compare * 100 * 0.9) + '%; ' +
						'min-width:60%" title="' +
						file.title + ' / ' + file.group + ' / ' + file.file + '">' +
						'</span> <span style="color:#000">' + file.hit +
						'</span></li>';
                }
                jQuery('.w3tcstackpath_file_hits').html(popuplar_html);
            }

			jQuery('.w3tcstackpath_content').removeClass('w3tc_hidden');
			jQuery('.w3tcstackpath_loading').addClass('w3tc_hidden');
		}
	).fail(function() {
		jQuery('.w3tcstackpath_error').removeClass('w3tc_none');
		jQuery('.w3tcstackpath_content').addClass('w3tc_hidden');
		jQuery('.w3tcstackpath_loading').addClass('w3tc_hidden');
	});
}



google.load("visualization", "1", {packages:["corechart"]});
google.setOnLoadCallback(w3tcstackpath_load);
