/**
 * File: PageSpeed_Widget_View.js
 *
 * JavaScript for the PageSpeed dashboard widget.
 *
 * @since 2.3.0 Update to utilize OAuth2.0 and overhaul of feature.
 *
 * @global w3tcData Localized data.
 */
jQuery(document).ready(function ($) {
	/**
	 * Analyze homepage via AJAX to Google PageSpeed Insights.
	 *
	 * @since 2.3.0
	 *
	 * @param boolean nocache Flag to enable/disable results cache.
	 *
	 * @return void
	 */
	function w3tcps_load(nocache) {
		$('.w3tcps_loading').removeClass('w3tc_none').find('.spinner').addClass('is-active');
		$('.w3tcps_timestamp_container').addClass('w3tc_none');
		$('.w3tcps_buttons').addClass('w3tc_none');
		$('.w3tc-gps-widget').addClass('w3tc_none');
		$('.w3tcps_error').addClass('w3tc_none');
		$.getJSON(ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
			'&w3tc_action=pagespeed_widgetdata' + (nocache ? '&cache=no' : ''),
			function (data) {
				$('.w3tcps_loading').addClass('w3tc_none').find('.spinner').removeClass('is-active');
				if (data.error) {
					$('.w3tcps_error').html(w3tcData.lang.pagespeed_widget_data_error + data.error);
					$('.w3tcps_error').removeClass('w3tc_none');
					return;
				} else if (data.missing_token) {
					$('.w3tcps_analyze').addClass('w3tc_none');
					$('.w3tcps_missing_token').html(data.missing_token);
					$('.w3tcps_missing_token').removeClass('w3tc_none');
					return;
				}
				$('.w3tcps_timestamp').html(data.w3tcps_timestamp);
				$('.w3tcps_timestamp_container').removeClass('w3tc_none');
				$('.w3tcps_buttons').removeClass('w3tc_none');
				$('.w3tc-gps-widget').html(data.w3tcps_widget);
				$('.w3tc-gps-widget').removeClass('w3tc_none').fadeIn('slow');
				$('#normal-sortables').masonry();
			}
		).fail(function (jqXHR, textStatus, errorThrown) {
			$('.w3tcps_error').html(w3tcData.lang.pagespeed_widget_data_error + jqXHR.responseText);
			$('.w3tcps_error').removeClass('w3tc_none');
			$('.w3tc-gps-widget').addClass('w3tc_none');
			$('.w3tcps_loading').addClass('w3tc_none').find('.spinner').removeClass('is-active');
		});
	}

	$('.w3tcps_buttons').on('click', '.w3tcps_refresh', function () {
		w3tcps_load(true);
	});

	w3tcps_load(false);
});
