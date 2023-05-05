import { CREATE_NOTICE, REMOVE_NOTICE } from './actions';

const notices = ( state = { notices: [] }, action ) => {
	switch ( action.type ) {
		case CREATE_NOTICE:
			return {
				...state,
				notices: [ ...state.notices, action.notice ],
			};
		case REMOVE_NOTICE:
			return {
				...state,
				notices: state.notices.filter( notice => notice.id !== action.notice.id ),
			};
	}
	return state;
};

export default notices;
