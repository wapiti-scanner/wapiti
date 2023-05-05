var w3tchw_graph_data;

function w3tchw_load() {
    jQuery('.w3tchw_loading').removeClass('w3tc_hidden');
    jQuery('.w3tchw_content').addClass('w3tc_hidden');
    jQuery('.w3tchw_error').addClass('w3tc_none');

    jQuery.getJSON(ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        '&w3tc_action=cdn_highwinds_widgetdata',
        function(data) {
            if (data && data.error) {
                jQuery('.w3tchw_error').removeClass('w3tc_none');
                jQuery('.w3tchw_error_details').html(data.error);
                jQuery('.w3tchw_loading').addClass('w3tc_hidden');
                return;
            }

            for (p in data) {
                var v = data[p];
                jQuery('.w3tchw_' + p).html(v);
            }

            var data = google.visualization.arrayToDataTable(data.graph);
            var options = {
                legend: { position: "none" },
              bars: 'horizontal'
            };

            var chart = new google.charts.Bar(document.getElementById('w3tchw_chart'));
            chart.draw(data, options);

            jQuery('.w3tchw_content').removeClass('w3tc_hidden');
            jQuery('.w3tchw_loading').addClass('w3tc_hidden');
        }
    ).fail(function() {
        jQuery('.w3tchw_error').removeClass('w3tc_none');
        jQuery('.w3tchw_content').addClass('w3tc_hidden');
        jQuery('.w3tchw_loading').addClass('w3tc_hidden');
    });
}



google.load("visualization", "1.1", {packages:["bar"]});
google.setOnLoadCallback(w3tchw_load);
