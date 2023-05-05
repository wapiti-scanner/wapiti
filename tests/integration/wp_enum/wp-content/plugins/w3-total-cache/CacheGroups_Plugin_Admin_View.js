/**
 * File: CacheGroups_Plugin_Admin_View.js
 *
 * @since 2.1.0
 *
 * @package W3TC
 */

jQuery(function() {

	// User agent groups.

	jQuery('#mobile_form').on( 'submit', function() {
		var error = false;

		jQuery('#mobile_groups li').each(function() {
			if (jQuery(this).find(':checked').length) {
				var group = jQuery(this).find('.mobile_group').text();
				var theme = jQuery(this).find(':selected').val();
				var redirect = jQuery(this).find('input[type=text]').val();
				var agents = jQuery.trim(jQuery(this).find('textarea').val()).split("\n");

				jQuery('#mobile_groups li').each(function() {
					if (jQuery(this).find(':checked').length) {
						var compare_group = jQuery(this).find('.mobile_group').text();
						if (compare_group != group) {
							var compare_theme = jQuery(this).find(':selected').val();
							var compare_redirect = jQuery(this).find('input[type=text]').val();
							var compare_agents = jQuery.trim(jQuery(this).find('textarea').val()).split("\n");

							if (compare_redirect == '' && redirect == '' && compare_theme != '' && compare_theme == theme) {
								alert('Duplicate theme "' + compare_theme + '" found in the group "' + group + '".');
								error = true;
								return false;
							}

							if (compare_redirect != '' && compare_redirect == redirect) {
								alert('Duplicate redirect "' + compare_redirect + '" found in the group "' + group + '".');
								error = true;
								return false;
							}

							jQuery.each(compare_agents, function(index, value) {
								if (jQuery.inArray(value, agents) != -1) {
									alert('Duplicate stem "' + value + '" found in the group "' + compare_group + '".');
									error = true;
									return false;
								}
							});
						}
					}
				});

				if (error) {
					return false;
				}
			}
		});

		if (error) {
			return false;
		}
	});

	jQuery('#mobile_add').on( 'click', function() {
		var group = prompt('Enter group name (only "0-9", "a-z", "_" symbols are allowed).');

		if (group !== null) {
			group = group.toLowerCase();
			group = group.replace(/[^0-9a-z_]+/g, '_');
			group = group.replace(/^_+/, '');
			group = group.replace(/_+$/, '');

			if (group) {
				var exists = false;

				jQuery('.mobile_group').each(function() {
					if (jQuery(this).html() == group) {
						alert('Group already exists!');
						exists = true;
						return false;
					}
				});

				if (!exists) {
					var li = jQuery('<li id="mobile_group_' + group + '"><table class="form-table"><tr><th>Group name:</th><td><span class="mobile_group_number">' + (jQuery('#mobile_groups li').length + 1) + '.</span> <span class="mobile_group">' + group + '</span> <input type="button" class="button mobile_delete" value="Delete group" /></td></tr><tr><th><label for="mobile_groups_' + group + '_enabled">Enabled:</label></th><td><input type="hidden" name="mobile_groups[' + group + '][enabled]" value="0" /><input id="mobile_groups_' + group + '_enabled" type="checkbox" name="mobile_groups[' + group + '][enabled]" value="1" checked="checked" /></td></tr><tr><th><label for="mobile_groups_' + group + '_theme">Theme:</label></th><td><select id="mobile_groups_' + group + '_theme" name="mobile_groups[' + group + '][theme]"><option value="">-- Pass-through --</option></select><p class="description">Assign this group of user agents to a specific them. Leaving this option "Active Theme" allows any plugins you have (e.g. mobile plugins) to properly handle requests for these user agents. If the "redirect users to" field is not empty, this setting is ignored.</p></td></tr><tr><th><label for="mobile_groups_' + group + '_redirect">Redirect users to:</label></th><td><input id="mobile_groups_' + group + '_redirect" type="text" name="mobile_groups[' + group + '][redirect]" value="" size="60" /><p class="description">A 302 redirect is used to send this group of users to another hostname (domain); recommended if a 3rd party service provides a mobile version of your site.</p></td></tr><tr><th><label for="mobile_groups_' + group + '_agents">User agents:</label></th><td><textarea id="mobile_groups_' + group + '_agents" name="mobile_groups[' + group + '][agents]" rows="10" cols="50"></textarea><p class="description">Specify the user agents for this group.</p></td></tr></table></li>');
					var select = li.find('select');

					jQuery.each(mobile_themes, function(index, value) {
						select.append(jQuery('<option />').val(index).html(value));
					});

					jQuery('#mobile_groups').append(li);
					w3tc_mobile_groups_clear();
					window.location.hash = '#mobile_group_' + group;
					li.find('textarea').focus();
				}
			} else {
				alert('Empty group name!');
			}
		}
	});

	jQuery('.mobile_delete').on('click', function () {
		if (confirm('Are you sure want to delete this group?')) {
			jQuery(this).parents('#mobile_groups li').remove();
			w3tc_mobile_groups_clear();
			w3tc_beforeupload_bind();
		}
	});

	w3tc_mobile_groups_clear();

	// Referrer groups.

	jQuery('#referrer_form').on( 'submit', function() {
		var error = false;

		jQuery('#referrer_groups li').each(function() {
			if (jQuery(this).find(':checked').length) {
				var group = jQuery(this).find('.referrer_group').text();
				var theme = jQuery(this).find(':selected').val();
				var redirect = jQuery(this).find('input[type=text]').val();
				var agents = jQuery.trim(jQuery(this).find('textarea').val()).split("\n");

				jQuery('#referrer_groups li').each(function() {
					if (jQuery(this).find(':checked').length) {
						var compare_group = jQuery(this).find('.referrer_group').text();
						if (compare_group != group) {
							var compare_theme = jQuery(this).find(':selected').val();
							var compare_redirect = jQuery(this).find('input[type=text]').val();
							var compare_agents = jQuery.trim(jQuery(this).find('textarea').val()).split("\n");

							if (compare_redirect == '' && redirect == '' && compare_theme != '' && compare_theme == theme) {
								alert('Duplicate theme "' + compare_theme + '" found in the group "' + group + '".');
								error = true;
								return false;
							}

							if (compare_redirect != '' && compare_redirect == redirect) {
								alert('Duplicate redirect "' + compare_redirect + '" found in the group "' + group + '".');
								error = true;
								return false;
							}

							jQuery.each(compare_agents, function(index, value) {
								if (jQuery.inArray(value, agents) != -1) {
									alert('Duplicate stem "' + value + '" found in the group "' + compare_group + '".');
									error = true;
									return false;
								}
							});
						}
					}
				});

				if (error) {
					return false;
				}
			}
		});

		if (error) {
			return false;
		}
	});

	jQuery('#referrer_add').on( 'click', function() {
		var group = prompt('Enter group name (only "0-9", "a-z", "_" symbols are allowed).');

		if (group !== null) {
			group = group.toLowerCase();
			group = group.replace(/[^0-9a-z_]+/g, '_');
			group = group.replace(/^_+/, '');
			group = group.replace(/_+$/, '');

			if (group) {
				var exists = false;

				jQuery('.referrer_group').each(function() {
					if (jQuery(this).html() == group) {
						alert('Group already exists!');
						exists = true;
						return false;
					}
				});

				if (!exists) {
					var li = jQuery('<li id="referrer_group_' + group + '"><table class="form-table"><tr><th>Group name:</th><td><span class="referrer_group_number">' + (jQuery('#referrer_groups li').length + 1) + '.</span> <span class="referrer_group">' + group + '</span> <input type="button" class="button referrer_delete" value="Delete group" /></td></tr><tr><th><label for="referrer_groups_' + group + '_enabled">Enabled:</label></th><td><input type="hidden" name="referrer_groups[' + group + '][enabled]" value="0" /><input id="referrer_groups_' + group + '_enabled" type="checkbox" name="referrer_groups[' + group + '][enabled]" value="1" checked="checked" /></td></tr><tr><th><label for="referrer_groups_' + group + '_theme">Theme:</label></th><td><select id="referrer_groups_' + group + '_theme" name="referrer_groups[' + group + '][theme]"><option value="">-- Pass-through --</option></select><p class="description">Assign this group of referrers to a specific them. Leaving this option "Active Theme" allows any plugins you have (e.g. referrer plugins) to properly handle requests for these referrers. If the "redirect users to" field is not empty, this setting is ignored.</p></td></tr><tr><th><label for="referrer_groups_' + group + '_redirect">Redirect users to:</label></th><td><input id="referrer_groups_' + group + '_redirect" type="text" name="referrer_groups[' + group + '][redirect]" value="" size="60" /><p class="description">A 302 redirect is used to send this group of users to another hostname (domain); recommended if a 3rd party service provides a referrer version of your site.</p></td></tr><tr><th><label for="referrer_groups_' + group + '_referrers">Referrers:</label></th><td><textarea id="referrer_groups_' + group + '_referrers" name="referrer_groups[' + group + '][referrers]" rows="10" cols="50"></textarea><p class="description">Specify the referrers for this group.</p></td></tr></table></li>');
					var select = li.find('select');

					jQuery.each(referrer_themes, function(index, value) {
						select.append(jQuery('<option />').val(index).html(value));
					});

					jQuery('#referrer_groups').append(li);
					w3tc_referrer_groups_clear();
					window.location.hash = '#referrer_group_' + group;
					li.find('textarea').focus();
				}
			} else {
				alert('Empty group name!');
			}
		}
	});

	jQuery('.referrer_delete').on('click', function () {
		if (confirm('Are you sure want to delete this group?')) {
			jQuery(this).parents('#referrer_groups li').remove();
			w3tc_referrer_groups_clear();
			w3tc_beforeupload_bind();
		}
	});

	w3tc_referrer_groups_clear();

	// Cookie groups.

	jQuery( '#w3tc_cookiegroup_add' ).on( 'click', function() {
		var group = prompt('Enter group name (only "0-9", "a-z", "_" symbols are allowed).');

		if (group !== null) {
			group = group.toLowerCase();
			group = group.replace(/[^0-9a-z_]+/g, '_');
			group = group.replace(/^_+/, '');
			group = group.replace(/_+$/, '');

			if (group) {
				var exists = false;

				jQuery('.cookiegroup_name').each(function() {
					if (jQuery(this).html() == group) {
						alert('Group already exists!');
						exists = true;
						return false;
					}
				});

				if (!exists) {
					var li = jQuery('<li id="cookiegroup_' + group + '">' +
						'<table class="form-table">' +
						'<tr>' +
						'<th>Group name:</th>' +
						'<td><span class="cookiegroup_number">' + (jQuery('#cookiegroups li').length + 1) + '.</span> ' +
						'<span class="cookiegroup_name">' + group + '</span> ' +
						'<input type="button" class="button cookiegroup_delete" value="Delete group" /></td>' +
						'</tr>' +
						'<tr>' +
						'<th><label for="cookiegroup_' + group + '_enabled">Enabled:</label></th>' +
						'<td>' +
						'<input id="cookiegroup_' + group + '_enabled" type="checkbox" name="cookiegroups[' +
						group + '][enabled]" value="1" checked="checked" /></td>' +
						'</tr>' +
						'<tr>' +
						'<th><label for="cookiegroup_' + group + '_cache">Cache:</label></th>' +
						'<td>' +
						'<input id="cookiegroup_' + group + '_cache" type="checkbox" name="cookiegroups[' +
						group + '][cache]" value="1" checked="checked" /></td></tr>' +
						'<tr>' +
						'<th><label for="cookiegroups_' + group + '_cookies">Cookies:</label></th>' +
						'<td><textarea id="cookiegroups_' + group + '_cookies" name="cookiegroups[' +
						group + '][cookies]" rows="10" cols="50"></textarea>' +
						'<p class="description">Specify the cookies for this group. Values like \'cookie\', \'cookie=value\', and cookie[a-z]+=value[a-z]+are supported. Remember to escape special characters like spaces, dots or dashes with a backslash. Regular expressions are also supported.</p></td></tr>' +
						'</table></li>');
					var select = li.find('select');

					jQuery('#cookiegroups').append(li);
					w3tc_cookiegroups_clear();
					window.location.hash = '#cookiegroup_' + group;
					li.find('textarea').focus();
				}
			} else {
				alert('Empty group name!');
			}
		}
	});

	jQuery('.w3tc_cookiegroup_delete').on( 'click', function () {
		if (confirm('Are you sure want to delete this group?')) {
			jQuery(this).parents('#cookiegroups li').remove();
			w3tc_cookiegroups_clear();
			w3tc_beforeupload_bind();
		}
	});

	w3tc_cookiegroups_clear();

	// Add sortable.
	if (jQuery.ui && jQuery.ui.sortable) {
		jQuery('#cookiegroups').sortable({
			axis: 'y',
			stop: function() {
				jQuery('#cookiegroups').find('.cookiegroup_number').each(function(index) {
					jQuery(this).html((index + 1) + '.');
				});
			}
		});
	}

});

function w3tc_mobile_groups_clear() {
	if (!jQuery('#mobile_groups li').length) {
		jQuery('#mobile_groups_empty').show();
	} else {
		jQuery('#mobile_groups_empty').hide();
	}
}

function w3tc_referrer_groups_clear() {
	if (!jQuery('#referrer_groups li').length) {
		jQuery('#referrer_groups_empty').show();
	} else {
		jQuery('#referrer_groups_empty').hide();
	}
}

function w3tc_cookiegroups_clear() {
	if (!jQuery('#cookiegroups li').length) {
		jQuery('#cookiegroups_empty').show();
	} else {
		jQuery('#cookiegroups_empty').hide();
	}
}
