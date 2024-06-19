import { StyleSheet, Text, View } from 'react-native';
import { TestStatus } from './App';

interface Props {
	testStatus: TestStatus;
	errorMessage: string;
}

export const TestFeedback = ({ testStatus, errorMessage }: Props) => {
	return (
		<View style={styles({ testStatus }).container}>
			<Text style={[styles({ testStatus }).text, styles({ testStatus }).title]}>
				{testStatus.toString()}
				{testStatus === 'RUNNING' ? '...' : ''}
			</Text>
			<Text
				style={[
					styles({ testStatus }).text,
					styles({ testStatus }).description,
				]}
			>
				{errorMessage}
			</Text>
		</View>
	);
};

const styles = ({ testStatus }: { testStatus: TestStatus }) =>
	StyleSheet.create({
		container: {
			flex: 1,
			backgroundColor:
				testStatus === 'ERROR'
					? 'red'
					: testStatus === 'RUNNING'
					  ? 'yellow'
					  : testStatus === 'SUCCESS'
						  ? 'green'
						  : 'gray',
			alignItems: 'center',
			justifyContent: 'center',
		},
		text: {
			color:
				testStatus === 'ERROR' || testStatus === 'SUCCESS' ? 'white' : 'black',
		},
		title: {
			fontSize: 24,
			fontWeight: '900',
		},
		description: {
			fontSize: 18,
			fontWeight: '600',
		},
	});
