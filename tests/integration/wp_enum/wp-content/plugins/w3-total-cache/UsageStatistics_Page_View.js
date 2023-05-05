jQuery(document).ready(function($) {
	var lastData;



	function load() {
        top_object = $('.ustats_top');
        $('.ustats_loading').removeClass('w3tc_hidden');
        $('.ustats_content').addClass('w3tc_hidden');
        $('.ustats_error').addClass('w3tc_none');
        $('.ustats_nodata').addClass('w3tc_none');

        $.getJSON(ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
            '&w3tc_action=ustats_get',
            function(data) {
				lastData = data;

				// show sections with data
				for (p in data) {
		            var v = data[p];
		            jQuery('.ustats_' + p).css('display', 'flex');
		        }

                setValues(data, 'ustats_');

                if (data.period.seconds)
                    $('.ustats_content').removeClass('w3tc_hidden');
                else
                    $('.ustats_nodata').removeClass('w3tc_none');

                $('.ustats_loading').addClass('w3tc_hidden');

				setCharts(data);

                setRefresh(
					(data && data.period ? data.period.to_update_secs : 0));

				showMetaboxes();
            }
        ).fail(function() {
            $('.ustats_error').removeClass('w3tc_none');
            $('.ustats_content').addClass('w3tc_hidden');
            $('.ustats_loading').addClass('w3tc_hidden');
        });
    }



	//
	// chart commons
	//
	var chartOptions = {
		//aspectRatio: 4,
		maintainAspectRatio: false,
		animation: false,
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
	var charts = {};



	function setCharts(data) {
		// collect functors that prepare data for their own chart
		var processors = [];
		processors.push(setChartsPageCache());
		processors.push(setChartsDb());
		processors.push(setChartsOc());
		processors.push(setChartsPhp());
		processors.push(setChartsCpu());
		processors.push(setChartsWpdb());
		processors.push(setChartsAccessLog());
		processors.push(setChartsMemcached());
		processors.push(setChartsRedis());
		processors.push(setChartsApc());

		// prepare collections
		var columnsToCollect = [];

		for (var i = 0; i < processors.length; i++) {
			for (var id in processors[i].chartDatasets) {
				var datasets = [];
				for (var i2 = 0; i2 < processors[i].chartDatasets[id].length; i2++) {
					var datasetTemplate = processors[i].chartDatasets[id][i2];
					var dataColumnString;
					if (Array.isArray(datasetTemplate.dataColumn)) {
						dataColumnString = datasetTemplate.dataColumn.join('.');
					} else {
						dataColumnString = datasetTemplate.dataColumn;
					}

					chartGraphValues[dataColumnString] = [];
					columnsToCollect.push({
						target: dataColumnString,
						column: datasetTemplate.dataColumn
					});
					datasets.push({
						label: datasetTemplate.label,
						data: chartGraphValues[dataColumnString],
						backgroundColor: datasetTemplate.backgroundColor
					});
				}

				charts[id].data.datasets = datasets;
			}
		}

		// collect data for charts
		var history = data.history;
		chartDateLabels.length = 0;
		for (var i = 0; i < history.length; i++) {
			var historyItem = history[i];
			var dateFormatted = '';
			if (history[i].timestamp_start) {
				var d = new Date(parseInt(history[i].timestamp_start) * 1000);
				dateFormatted = dateFormat(d);
			}

			chartDateLabels.push(dateFormatted);

			// custom preprocess history row
			for (var i2 = 0; i2 < processors.length; i2++) {
				if (processors[i2].preprocess) {
					processors[i2].preprocess(historyItem);
				}
			}

			// collect metrics for graphs
			for (var i2 = 0; i2 < columnsToCollect.length; i2++) {
				var c = columnsToCollect[i2];
				var v;
				if (Array.isArray(c.column)) {
					if (v = historyItem[c.column[0]]) {
						v = historyItem[c.column[0]][c.column[1]];
					}
				} else {
					v = historyItem[c.column];
				}

				chartGraphValues[c.target].push(v);
			}
		}

		// visualize
		for (var c in charts) {
			charts[c].update();
		}
	}



	$('.w3tcus_chart_check').click(function() {
		setCharts(lastData);
	});



	//
	// PageCache chart
	//
	function setChartsPageCache() {
		if (!charts['pagecache']) {
			var ctx = $('#w3tcus_pagecache_chart');
			charts['pagecache'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels,
			    },
			    options: chartOptions
			});
		}


		return {
			chartDatasets: {
				pagecache: [{
						label: 'Time (ms)',
						dataColumn: 'pagecache_requests_time_ms',
						backgroundColor: '#0073aa'
					}
				]
			},
			preprocess: function(historyItem) {
				v = 0;
				if (historyItem.pagecache_requests_time_10ms && historyItem.php_requests) {
					v = ((historyItem.pagecache_requests_time_10ms * 10) /
					 	historyItem.php_requests).toFixed(0);
				}
				historyItem.pagecache_requests_time_ms = v;
			}
		};
	}



	//
	// Database chart
	//
	function setChartsDb() {
		if (!charts['db']) {
			var ctx = $('#w3tcus_dbcache_chart');
			charts['db'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels,
			    },
			    options: chartOptions
			});

			var ctx = $('#w3tcus_dbcache_time_chart');
			charts['db_time'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels,
			    },
			    options: chartOptions
			});
		}


		return {
			chartDatasets: {
				db_time: [{
						label: 'Time (ms)',
						dataColumn: 'dbcache_time_ms',
						backgroundColor: '#0073aa'
					}
				],
				db: [{
						label: 'Calls',
						dataColumn: 'dbcache_calls_total',
						backgroundColor: '#0073aa'
					}, {
						label: 'Hits',
						dataColumn: 'dbcache_calls_hits',
						backgroundColor: 'green'
					}
				]
			}
		};
	}



	//
	// OC chart
	//
	function setChartsOc(data) {
		if (!charts['oc']) {
			var ctx = $('#w3tcus_objectcache_chart');
			charts['oc'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels
			    },
			    options: chartOptions
			});

			var ctx = $('#w3tcus_objectcache_time_chart');
			charts['oc_time'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels
			    },
			    options: chartOptions
			});
		}

		return {
			chartDatasets: {
				oc_time: [{
						label: 'Time (ms)',
						dataColumn: 'objectcache_time_ms',
						backgroundColor: '#0073aa'
					}
				],
				oc: [{
						label: 'Gets',
						dataColumn: 'objectcache_get_total',
						backgroundColor: '#0073aa'
					}, {
						label: 'Hits',
						dataColumn: 'objectcache_get_hits',
						backgroundColor: 'green'
					}, {
						label: 'Sets',
						dataColumn: 'objectcache_sets',
						backgroundColor: 'red'
					}
				]
			}
		};
	}



	//
	// PHP chart
	//
	function setChartsPhp(data) {
		if (!charts['phpMemory']) {
			var ctx = $('#w3tcus_php_memory_chart');
			charts['phpMemory'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels,
			    },
			    options: chartOptions
			});
		}
		if (!charts['phpRequests']) {
			var ctx = $('#w3tcus_php_requests_chart');
			charts['phpRequests'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels
			    },
			    options: chartOptions
			});
		}

		var phpRequestsDatasets = [];
		$('.w3tcus_chart_check').each(function() {
			if ($(this).is(':checked')) {
				var dataColumn = $(this).data('column');
				var backgroundColor = $(this).data('background');
				if (!backgroundColor) {
					backgroundColor = '#0073aa';
				}

				if (startsWith(dataColumn, 'php_php_requests')) {
					phpRequestsDatasets.push({
						label: $(this).data('name'),
						dataColumn: dataColumn.substr(4),
						backgroundColor: backgroundColor
					});
				}
			}
		});

		return {
			chartDatasets: {
				phpMemory: [{
						label: 'MB',
						dataColumn: 'php_memory_mb',
						backgroundColor: '#0073aa'
					}
				],
				phpRequests: phpRequestsDatasets
			},
			preprocess: function(historyItem) {
				var v = 0;
				if (historyItem.php_requests) {
					v = (historyItem.php_memory_100kb / 100.0 / historyItem.php_requests).toFixed(2)
				}
				historyItem.php_memory_mb = v;

				historyItem.php_requests_pagecache_miss =
					historyItem.php_requests - historyItem.php_requests_pagecache_hit;
			}
		};
	}



	//
	// CPU chart
	//
	function setChartsCpu(data) {
		if (!charts['cpu']) {
			var ctx = $('#w3tcus_cpu_chart');
			charts['cpu'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels,
			    },
			    options: chartOptions
			});
		}

		return {
			chartDatasets: {
				cpu: [{
						label: 'CPU',
						dataColumn: 'cpu',
						backgroundColor: '#0073aa'
					}
				]
			}
		};
	}



	//
	// WPDB chart
	//
	function setChartsWpdb(data) {
		if (!charts['wpdb']) {
			var ctx = $('#w3tcus_wpdb_chart');
			charts['wpdb'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels,
			    },
			    options: chartOptions
			});
		}

		return {
			chartDatasets: {
				wpdb: [{
					label: 'Total',
					dataColumn: 'wpdb_calls_total',
					backgroundColor: '#0073aa'
				}]
			}
		};
	}



	//
	// Access Log chart
	//
	function setChartsAccessLog(data) {
		if (!charts['accessLogRequests']) {
			var ctx = $('#w3tcus_access_log_chart_requests');
			charts['accessLogRequests'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels,
			    },
			    options: chartOptions
			});
		}
		if (!charts['accessLogTiming']) {
			var ctx = $('#w3tcus_access_log_chart_timing');
			charts['accessLogTiming'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels
			    },
			    options: chartOptions
			});
		}

		return {
			chartDatasets: {
				accessLogRequests: [{
						label: 'Dynamic',
						dataColumn: ['access_log', 'dynamic_count'],
						backgroundColor: '#0073aa'
					}, {
						label: 'Static',
						dataColumn: ['access_log', 'static_count'],
						backgroundColor: '#0073aa'
					}
				],
				accessLogTiming: [{
						label: 'Dynamic',
						dataColumn: ['access_log', 'dynamic_timing'],
						backgroundColor: '#0073aa'
					}, {
						label: 'Static',
						dataColumn: ['access_log', 'static_timing'],
						backgroundColor: '#0073aa'
					}
				]
			},
			preprocess: function(historyItem) {
				var dc = 0, sc = 0, dt = 0, st = 0;
				if (historyItem.access_log) {
					var a = historyItem.access_log;
					dc = a.dynamic_count;
					if (dc) {
						dt = (a.dynamic_timetaken_ms / dc).toFixed(2);
					}

					sc = a.static_count;
					if (sc) {
						st = (a.static_timetaken_ms / dc).toFixed(2);
					}

					historyItem['access_log']['dynamic_timing'] = dt;
					historyItem['access_log']['static_timing'] = st;
				}
			}
		};
	}



	//
	// Memcached chart
	//
	function setChartsMemcached(data) {
		if (!charts['memcachedSize']) {
			var ctx = $('#w3tcus_memcached_size_chart');
			charts['memcachedSize'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels
			    },
			    options: chartOptions
			});
		}

		if (!charts['memcachedHit']) {
			var ctx = $('#w3tcus_memcached_hit_chart');
			charts['memcachedHit'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels
			    },
			    options: chartOptions
			});
		}

		var prevCalls = -1;
		var prevHits = -1;

		return {
			chartDatasets: {
				memcachedSize: [{
		            label: 'MB',
		            dataColumn: 'memcached_size_mb',
		            backgroundColor: '#0073aa'
		        }],
				memcachedHit: [{
						label: 'Calls',
						dataColumn: 'memcached_requests_total',
						backgroundColor: '#0073aa'
					}, {
						label: 'Hits',
						dataColumn: 'memcached_requests_hits',
						backgroundColor: 'green'
					}
				]
			},
			preprocess: function(historyItem) {
				var size = 0;
				var calls = 0;
				var hits = 0;
				if (historyItem.memcached && historyItem.memcached.size_used) {
					size = (historyItem.memcached.size_used / 1024.0 / 1024.0).toFixed(2);
					if (prevCalls >= 0 && historyItem.memcached.get_calls >= prevCalls) {
						calls = historyItem.memcached.get_calls - prevCalls;
						hits = historyItem.memcached.get_hits - prevHits;
					}

					if (calls > 10000) {
						calls = 0;
						hits = 0;
					}
					prevCalls = historyItem.memcached.get_calls;
					prevHits = historyItem.memcached.get_hits;
				}

				historyItem.memcached_size_mb = size;
				historyItem.memcached_requests_total = calls;
				historyItem.memcached_requests_hits = hits;
			}
		};
	}



	//
	// Redis chart
	//
	function setChartsRedis(data) {
		if (!charts['redisSize']) {
			var ctx = $('#w3tcus_redis_size_chart');
			charts['redisSize'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels
			    },
			    options: chartOptions
			});
		}

		if (!charts['redisHit']) {
			var ctx = $('#w3tcus_redis_hit_chart');
			charts['redisHit'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels
			    },
			    options: chartOptions
			});
		}

		var prevCalls = -1;
		var prevHits = -1;

		return {
			chartDatasets: {
				redisSize: [{
		            label: 'MB',
		            dataColumn: 'redis_size_mb',
		            backgroundColor: '#0073aa'
		        }],
				redisHit: [{
						label: 'Calls',
						dataColumn: 'redis_requests_total',
						backgroundColor: '#0073aa'
					}, {
						label: 'Hits',
						dataColumn: 'redis_requests_hits',
						backgroundColor: 'green'
					}
				]
			},
			preprocess: function(historyItem) {
				var size = 0;
				var calls = 0;
				var hits = 0;
				if (historyItem.redis && historyItem.redis.size_used) {
					size = (historyItem.redis.size_used / 1024.0 / 1024.0).toFixed(2);
					if (prevCalls >= 0 && historyItem.redis.get_calls >= prevCalls) {
						calls = historyItem.redis.get_calls - prevCalls;
						hits = historyItem.redis.get_hits - prevHits;
					}

					if (calls > 10000) {
						calls = 0;
						hits = 0;
					}
					prevCalls = historyItem.redis.get_calls;
					prevHits = historyItem.redis.get_hits;
				}

				historyItem.redis_size_mb = size;
				historyItem.redis_requests_total = calls;
				historyItem.redis_requests_hits = hits;
			}
		};
	}



	//
	// APC chart
	//
	function setChartsApc(data) {
		if (!charts['apcSize']) {
			var ctx = $('#w3tcus_apc_size_chart');
			charts['apcSize'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels
			    },
			    options: chartOptions
			});
		}

		if (!charts['apcHit']) {
			var ctx = $('#w3tcus_apc_hit_chart');
			charts['apcHit'] = new Chart(ctx, {
			    type: 'bar',
			    data: {
			        labels: chartDateLabels
			    },
			    options: chartOptions
			});
		}

		var prevCalls = -1;
		var prevHits = -1;

		return {
			chartDatasets: {
				apcSize: [{
		            label: 'MB',
		            dataColumn: 'apc_size_mb',
		            backgroundColor: '#0073aa'
		        }],
				apcHit: [{
						label: 'Calls',
						dataColumn: 'apc_requests_total',
						backgroundColor: '#0073aa'
					}, {
						label: 'Hits',
						dataColumn: 'apc_requests_hits',
						backgroundColor: 'green'
					}
				]
			},
			preprocess: function(historyItem) {
				var size = 0;
				var calls = 0;
				var hits = 0;
				if (historyItem.apc && historyItem.apc.size_used) {
					size = (historyItem.apc.size_used / 1024.0 / 1024.0).toFixed(2);
					if (prevCalls >= 0 && historyItem.apc.get_total >= prevCalls) {
						calls = historyItem.apc.get_total - prevCalls;
						hits = historyItem.apc.get_hits - prevHits;
					}

					if (calls > 10000) {
						calls = 0;
						hits = 0;
					}
					prevCalls = historyItem.apc.get_total;
					prevHits = historyItem.apc.get_hits;
				}

				historyItem.apc_size_mb = size;
				historyItem.apc_requests_total = calls;
				historyItem.apc_requests_hits = hits;
			}
		};
	}



	//
	// Utils
	//
	function startsWith(s, prefix) {
		return s && s.substr(0, prefix.length) == prefix;
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
                jQuery('.' + css_class_prefix + p + ' span').html(v);
				if (jQuery('.' + css_class_prefix + p).hasClass('w3tcus_inline')) {
					jQuery('.' + css_class_prefix + p).css('display', 'inline');
				} else {
					jQuery('.' + css_class_prefix + p).css('display', 'block');
				}
            }
        }
    }



    var seconds_timer_id;
    function setRefresh(new_seconds_till_refresh) {
        clearTimeout(seconds_timer_id);
        var seconds_till_refresh = new_seconds_till_refresh;

        seconds_timer_id = setInterval(function() {
            seconds_till_refresh--;
            if (seconds_till_refresh <= 0) {
                clearTimeout(seconds_timer_id);
                seconds_timer_id = null;
				load();
                return;
            }

            jQuery('.ustats_reload').text('Will be recalculated in ' +
                seconds_till_refresh + ' second' +
                (seconds_till_refresh > 1 ? 's' : ''));
        }, 1000);
    }



	function showMetaboxes() {
		jQuery('.metabox-holder').each(function() {
			var visible = false;
			jQuery(this).find('.ustats_block').each(function() {
				visible |= jQuery(this).css('display') != 'none';
			});

			jQuery(this).css('display', (visible ? '' : 'none'));
		});
	}


	//
	// Main entry
	//
    load();

    $('.ustats_reload').click(function(e) {
        event.preventDefault();
        load();
    })
});
