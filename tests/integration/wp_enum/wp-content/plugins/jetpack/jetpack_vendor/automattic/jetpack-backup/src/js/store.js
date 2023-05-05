import actions from './actions';
import reducer from './reducers';
import selectors from './selectors';

export const STORE_ID = 'jetpack-backup-plugin';
export const storeConfig = {
	__experimentalUseThunks: true,
	reducer,
	selectors,
	initialState: window.JPBACKUP_INITIAL_STATE || {},
	actions,
};
