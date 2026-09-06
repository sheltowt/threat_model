import { z } from 'zod';
import { modelSchema } from './schema.js';
import { builtinCatalog } from './catalog-core.js';

/**
 * Emit the JSON Schema that editors use for completion and inline validation.
 *
 * Generating it from the Zod schema rather than maintaining it by hand is the fix
 * for Threat Dragon's schema drift, where the published schema declares `threatId`
 * and puts threats at cell level while every real file uses `data.threats[].id`.
 * Here the schema cannot disagree with the validator because it is the validator.
 *
 * Technology and protocol enums are injected from the catalogue so completion lists
 * the real values, while still allowing a project-defined name.
 */
export function modelJsonSchema(): Record<string, unknown> {
  const base = z.toJSONSchema(modelSchema, { io: 'input', target: 'draft-2020-12' }) as Record<
    string,
    unknown
  >;
  const catalog = builtinCatalog();

  const defs = (base['$defs'] ?? {}) as Record<string, unknown>;
  const props = (base['properties'] ?? {}) as Record<string, unknown>;

  // Annotate the two catalogue-backed string fields with their known values.
  const annotate = (node: unknown, values: string[], title: string): void => {
    if (typeof node !== 'object' || node === null) return;
    const obj = node as Record<string, unknown>;
    obj['examples'] = values;
    obj['title'] = title;
  };

  const elements = props['elements'] as Record<string, unknown> | undefined;
  const elementProps = (
    (elements?.['additionalProperties'] as Record<string, unknown> | undefined)?.[
      'properties'
    ] as Record<string, unknown> | undefined
  );
  if (elementProps) {
    annotate(
      elementProps['technology'],
      [...catalog.technologies.keys()],
      'Technology from the catalogue',
    );
  }

  const flows = props['flows'] as Record<string, unknown> | undefined;
  const flowProps = (flows?.['items'] as Record<string, unknown> | undefined)?.['properties'] as
    | Record<string, unknown>
    | undefined;
  if (flowProps) {
    annotate(flowProps['protocol'], [...catalog.protocols.keys()], 'Protocol from the catalogue');
  }

  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://tmc.dev/schema/tmc-1.0.json',
    title: 'tmc threat model',
    description:
      'Declarative threat model. Security controls are tri-state: omit a control to say it is unknown rather than absent.',
    ...base,
    $defs: defs,
  };
}
