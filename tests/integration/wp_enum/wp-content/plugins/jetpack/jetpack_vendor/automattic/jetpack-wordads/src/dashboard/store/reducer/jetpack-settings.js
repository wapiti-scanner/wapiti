import { SET_WORDADS_SETTINGS } from '../actions/jetpack-settings';

const jetpackSettings = ( state = {}, action ) => {
	switch ( action.type ) {
		case SET_WORDADS_SETTINGS:
			return {
				...state,
				...action.options,
				is_toggling_module:
					state.module_active !== action.options.module_active && !! action.options.is_updating,
				is_toggling_instant_search:
					state.instant_search_enabled !== action.options.instant_search_enabled &&
					!! action.options.is_updating,
			};
	}
	return state;
};

export default jetpackSettings;
