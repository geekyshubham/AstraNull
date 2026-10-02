export type TargetGroupLabelState = 'ungrouped' | 'named' | 'unavailable' | 'unrecorded';

export type TargetGroupLabel = {
  state: TargetGroupLabelState;
  id: string;
  name: string;
};

export function buildTargetGroupNameMap(targetGroups: unknown): Map<string, string>;

export function resolveTargetGroupLabel(
  groupId: unknown,
  options?: { names?: Map<string, string>; loadError?: string | null }
): TargetGroupLabel;
