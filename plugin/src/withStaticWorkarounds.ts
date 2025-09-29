import { type ConfigPlugin, withPodfile } from '@expo/config-plugins';

export interface StaticWorkaroundOptions {
	ios?: {
		disableStaticWorkarounds?: boolean;
		staticPods?: string[]; // extra pod names
	};
}

// Minimal default set: only pods that commonly break under use_frameworks! :dynamic
const DEFAULT_STATIC_PODS = ['RNReanimated', 'RNScreens'];

function buildPreInstallBlock(pods: string[]) {
	return `
pre_install do |installer|
  installer.pod_targets.each do |pod|
    case pod.name
${pods
	.map(
		(p) => `    when '${p}'
      def pod.build_type; Pod::BuildType.static_library; end`
	)
	.join('\n')}
    end
  end
end`.trim();
}

function injectBlock(contents: string, pods: string[]) {
	const markerStart =
		'# >>> react-native-libsignal-client static pod workarounds >>>';
	const markerEnd =
		'# <<< react-native-libsignal-client static pod workarounds <<<';

	if (contents.includes(markerStart)) return contents;
	const block = `${markerStart}\n${buildPreInstallBlock(pods)}\n${markerEnd}`;
	return `${contents.trimEnd()}\n\n${block}\n`;
}

const withStaticWorkarounds: ConfigPlugin<
	StaticWorkaroundOptions | undefined
> = (config, props) =>
	withPodfile(config, (cfg) => {
		if (props?.ios?.disableStaticWorkarounds) return cfg;
		const extra = props?.ios?.staticPods ?? [];
		const pods = Array.from(new Set([...DEFAULT_STATIC_PODS, ...extra]));
		cfg.modResults.contents = injectBlock(cfg.modResults.contents, pods);
		return cfg;
	});

export default withStaticWorkarounds;
