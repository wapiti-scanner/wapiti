jQuery(document).ready(function($) {
	var lastData;



	function load() {
        $.getJSON(ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
            '&w3tc_action=ustats_get',
            function(data) {
				lastData = data;

                setValues(data, 'w3tcuw_');
				setChart(data);
            }
        ).fail(function() {
			console.log('failed to load widget data');
        });
    }



	//
	// chart commons
	//
	var chartOptions = {
		//aspectRatio: 4,
		maintainAspectRatio: false,
		height: '200px',
		legend: false,
		scales: {
			yAxes: [{
				ticks: {
					beginAtZero: true
				}
			}]
		}
	};



	var chartDateLabels = [];
	var chartGraphValues = {};
	var chartObject;



	function setChart(data) {
		var ctx = $('#w3tcuw_chart');
		chartObject = new Chart(ctx, {
			type: 'line',
			data: {
				labels: chartDateLabels,
			},
			options: chartOptions
		});

		// collect functors that prepare data for their own chart
		var datasetTemplates = [];
		datasetTemplates.push(setChartsDbCache());
		datasetTemplates.push(setChartsObjectCache());
		datasetTemplates.push(setChartsPageCache());

		// prepare collections
		var datasets = [];

		for (var i = 0; i < datasetTemplates.length; i++) {
			var datasetTemplate = datasetTemplates[i];
			var datasetName = datasetTemplate.name;

			chartGraphValues[datasetName] = [];
			datasets.push({
				label: datasetTemplate.label,
				data: chartGraphValues[datasetName],
				borderColor: datasetTemplate.borderColor,
				fill: false
			});
		}

		chartObject.data.datasets = datasets;

		// collect data for charts
		var history = data.history;
		chartDateLabels.length = 0;
		var averagesToCollect = Math.floor(history.length / 10);
		if (averagesToCollect <= 1) {
			averagesToCollect = 1;
		}

		var averages = {};
		var averagesCollected = 0;

		for (var i = 0; i < history.length; i++) {
			var historyItem = history[i];

			// collect metrics for graphs
			for (var i2 = 0; i2 < datasetTemplates.length; i2++) {
				var c = datasetTemplates[i2];
				var v = c.valueFunctor(historyItem) * 100;
				averages[i2] = (!averages[i2] ? 0 : averages[i2]) + v;
			}

			averagesCollected++;
			if (averagesCollected >= averagesToCollect) {
				var dateFormatted = '';
				if (history[i].timestamp_start) {
					var d = new Date(parseInt(history[i].timestamp_start) * 1000);
					dateFormatted = dateFormat(d);
				}

				chartDateLabels.push(dateFormatted);

				for (var i2 = 0; i2 < datasetTemplates.length; i2++) {
					var c = datasetTemplates[i2];
					var v = (averages[i2] / averagesCollected).toFixed(2);
					chartGraphValues[c.name].push(v);
				}

				averages = {};
				averagesCollected = 0;
			}
		}

		// visualize
		chartObject.update();
	}



	//
	// chart data
	//
	function setChartsDbCache() {
		return {
			label: 'Database cache',
			name: 'dbcache_hit_rate',
			valueFunctor: function(i) {
				return i.dbcache_calls_total == 0 ? 0 :
					i.dbcache_calls_hits / i.dbcache_calls_total;
			},
			borderColor: '#0073aa'
		};
	}



	function setChartsObjectCache() {
		return {
			label: 'Object cache',
			name: 'objectcache_hit_rate',
			valueFunctor: function(i) {
				return i.objectcache_get_total == 0 ? 0 :
					i.objectcache_get_hits / i.objectcache_get_total;
			},
			borderColor: 'green'
		};
	}



	function setChartsPageCache() {
		return {
			label: 'Page cache',
			name: 'pagecache_hit_rate',
			valueFunctor: function(i) {
				return i.php_requests == 0 ? 0 :
					i.php_requests_pagecache_hit / i.php_requests;
			},
			borderColor: 'blue'
		};
	}



	//
	// Utils
	//
	function startsWith(s, prefix) {
		return s.substr(0, prefix.length) == prefix;
	}



	function dateFormat(d) {
		return ("0" + d.getUTCHours()).slice(-2) + ":" +
			("0" + d.getUTCMinutes()).slice(-2);
	}



	function setValues(data, css_class_prefix) {
        for (p in data) {
            var v = data[p];
            if (typeof(v) != 'string' && typeof(v) != 'number')
                setValues(v, css_class_prefix + p + '_');
            else {
                jQuery('.' + css_class_prefix + p + ' .w3tcuw_value').html(v);
				jQuery('.' + css_class_prefix + p).css('display', 'block');
            }
        }
    }



	//
	// Main entry
	//
    load();
});
