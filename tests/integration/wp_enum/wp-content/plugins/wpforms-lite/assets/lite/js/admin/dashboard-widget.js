/* global wpforms_dashboard_widget, moment, Chart, ajaxurl */
/**
 * WPForms Dashboard Widget function.
 *
 * @since 1.5.0
 */

'use strict';

var WPFormsDashboardWidget = window.WPFormsDashboardWidget || ( function( document, window, $ ) {

	/**
	 * Elements reference.
	 *
	 * @since 1.5.0
	 *
	 * @type {object}
	 */
	var el = {
		$widget:               $( '#wpforms_reports_widget_lite' ),
		$settingsBtn:          $( '#wpforms-dash-widget-settings-button' ),
		$canvas:               $( '#wpforms-dash-widget-chart' ),
		$dismissBtn:           $( '.wpforms-dash-widget-dismiss-chart-upgrade' ),
		$recomBlockDismissBtn: $( '#wpforms-dash-widget-dismiss-recommended-plugin-block' ),
	};

	/**
	 * Chart.js functions and properties.
	 *
	 * @since 1.5.0
	 *
	 * @type {object}
	 */
	var chart = {

		/**
		 * Chart.js instance.
		 *
		 * @since 1.5.0
		 */
		instance: null,

		/**
		 * Chart.js settings.
		 *
		 * @since 1.5.0
		 */
		settings: {
			type   : 'line',
			data   : {
				labels  : [],
				datasets: [ {
					label               : wpforms_dashboard_widget.i18n.entries,
					data                : [],
					backgroundColor     : 'rgba(255, 129, 0, 0.135)',
					borderColor         : 'rgba(211, 126, 71, 1)',
					borderWidth         : 2,
					pointRadius         : 4,
					pointBorderWidth    : 1,
					pointBackgroundColor: 'rgba(255, 255, 255, 1)',
				} ],
			},
			options: {
				scales                     : {
					xAxes: [ {
						type        : 'time',
						time        : {
							unit: 'day',
						},
						distribution: 'series',
						ticks       : {
							beginAtZero: true,
							source     : 'labels',
							padding    : 10,
							minRotation: 25,
							maxRotation: 25,
							callback   : function( value, index, values ) {

								// Distribute the ticks equally starting from a right side of xAxis.
								var gap = Math.floor( values.length / 7 );

								if ( gap < 1 ) {
									return value;
								}
								if ( ( values.length - index - 1 ) % gap === 0 ) {
									return value;
								}
							},
						},
					} ],
					yAxes: [ {
						ticks: {
							beginAtZero  : true,
							maxTicksLimit: 6,
							padding      : 20,
							callback     : function( value ) {

								// Make sure the tick value has no decimals.
								if ( Math.floor( value ) === value ) {
									return value;
								}
							},
						},
					} ],
				},
				elements                   : {
					line: {
						tension: 0,
					},
				},
				animation                  : {
					duration: 0,
				},
				hover                      : {
					animationDuration: 0,
				},
				legend                     : {
					display: false,
				},
				tooltips                   : {
					displayColors: false,
				},
				responsiveAnimationDuration: 0,
				maintainAspectRatio: false,
			},
		},

		/**
		 * Init Chart.js.
		 *
		 * @since 1.5.0
		 */
		init: function() {

			var ctx;

			if ( ! el.$canvas.length ) {
				return;
			}

			ctx = el.$canvas[ 0 ].getContext( '2d' );

			chart.instance = new Chart( ctx, chart.settings );

			chart.updateUI();
		},

		/**
		 * Update Chart.js canvas.
		 *
		 * @since 1.5.0
		 */
		updateUI: function() {

			chart.updateWithDummyData();

			chart.instance.data.labels = chart.settings.data.labels;
			chart.instance.data.datasets[ 0 ].data = chart.settings.data.datasets[ 0 ].data;

			chart.instance.update();
		},

		/**
		 * Update Chart.js settings with dummy data.
		 *
		 * @since 1.5.0
		 */
		updateWithDummyData: function() {

			var end = moment().endOf( 'day' );
			var date;

			var minY = 5;
			var maxY = 20;
			var i;

			for ( i = 1; i <= 7; i++ ) {

				date = end.clone().subtract( i, 'days' );

				chart.settings.data.labels.push( date );
				chart.settings.data.datasets[ 0 ].data.push( {
					t: date,
					y: Math.floor( Math.random() * ( maxY - minY + 1 ) ) + minY,
				} );
			}
		},
	};

	/**
	 * Public functions and properties.
	 *
	 * @since 1.5.0
	 *
	 * @type {object}
	 */
	var app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.5.0
		 */
		init: function() {

			$( app.ready );
		},

		/**
		 * Document ready.
		 *
		 * @since 1.5.0
		 */
		ready: function() {

			chart.init();
			app.events();
			app.graphSettings();
		},

		/**
		 * Graph settings related events.
		 *
		 * @since 1.7.4
		 */
		graphSettings: function() {

			el.$settingsBtn.on( 'click', function() {

				$( this ).siblings( '.wpforms-dash-widget-settings-menu' ).toggle();
			} );
		},

		/**
		 * Register JS events.
		 *
		 * @since 1.5.0
		 */
		events: function() {

			app.formsListEvents();
			app.handleChartClose();
			app.handleRecommendedPluginsClose();
		},

		/**
		 * Register forms list area JS events.
		 *
		 * @since 1.5.0
		 */
		formsListEvents: function() {

			el.$widget.on( 'click', '#wpforms-dash-widget-forms-more', function() {

				app.toggleCompleteFormsList();
			} );
		},

		/**
		 * Handle chart close.
		 *
		 * @since 1.7.4
		 */
		handleChartClose: function() {

			el.$dismissBtn.on( 'click', function( event ) {

				event.preventDefault();
				app.saveWidgetMeta( 'hide_graph', 1 );
				$( '.wpforms-dash-widget.wpforms-lite' ).addClass( 'wpforms-dash-widget-no-graph' );
				$( this ).closest( '.wpforms-dash-widget-chart-block-container' ).remove();
			} );
		},

		/**
		 * Handle recommended plugins block close.
		 *
		 * @since 1.7.4
		 */
		handleRecommendedPluginsClose: function() {

			el.$recomBlockDismissBtn.on( 'click', function() {
				app.dismissRecommendedBlock();
			} );
		},

		/**
		 * Save dashboard widget meta on a backend.
		 *
		 * @since 1.7.4
		 *
		 * @param {string} meta Meta name to save.
		 * @param {number} value Value to save.
		 */
		saveWidgetMeta: function( meta, value ) {

			const data = {
				_wpnonce: wpforms_dashboard_widget.nonce,
				action  : 'wpforms_' + wpforms_dashboard_widget.slug + '_save_widget_meta',
				meta    : meta,
				value   : value,
			};

			$.post( ajaxurl, data );
		},

		/**
		 * Toggle forms list hidden entries.
		 *
		 * @since 1.5.0.4
		 */
		toggleCompleteFormsList: function() {

			$( '#wpforms-dash-widget-forms-list-table .wpforms-dash-widget-forms-list-hidden-el' ).toggle();
			$( '#wpforms-dash-widget-forms-more' ).html( function( i, html ) {

				return html === wpforms_dashboard_widget.show_less_html ? wpforms_dashboard_widget.show_more_html : wpforms_dashboard_widget.show_less_html;
			} );
		},

		/**
		 * Dismiss recommended plugin block.
		 *
		 * @since 1.7.4
		 */
		dismissRecommendedBlock: function() {

			$( '.wpforms-dash-widget-recommended-plugin-block' ).remove();
			app.saveWidgetMeta( 'hide_recommended_block', 1 );
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );

// Initialize.
WPFormsDashboardWidget.init();
