import { useMemo } from 'react';
import useConnection from '../../hooks/useConnection';

export const useIsFullyConnected = () => {
	const [ connectionStatus ] = useConnection();

	return useMemo( () => {
		const connectionLoaded = 0 < Object.keys( connectionStatus ).length;
		return connectionLoaded && connectionStatus.hasConnectedOwner && connectionStatus.isRegistered;
	}, [ connectionStatus ] );
};
