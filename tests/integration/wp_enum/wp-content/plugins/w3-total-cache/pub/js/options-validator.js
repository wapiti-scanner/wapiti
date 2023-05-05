jQuery(document).ready(function() {
	jQuery('textarea[w3tc-data-validator="regexps"]').change(function() {
		var v = jQuery(this).val();
		var items = v.split("\n");

		for (var n = 0; n < items.length; n++) {
			var regexp = items[n].trim();
			if (regexp.length > 0) {
				try {
					new RegExp(regexp);
				} catch(e) {
					var error = 'Contains invalid regexp ' + regexp +', please fix';
					console.log(error);
					jQuery(this)[0].setCustomValidity(error);
					return;
				}
			}
		}

		jQuery(this)[0].setCustomValidity('');
	});
});
