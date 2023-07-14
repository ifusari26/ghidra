/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.debug.workflow;

import java.util.*;

import ghidra.app.services.*;
import ghidra.app.services.SectionMapProposal.SectionMapEntry;
import ghidra.framework.options.annotation.HelpInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceSectionChangeType;
import ghidra.trace.util.TraceChangeType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@DebuggerBotInfo( //
	description = "Map sections to open programs", //
	details = "Monitors open traces and programs, attempting to map sections by \"best\" match.", //
	help = @HelpInfo(anchor = "map_sections"), //
	enabledByDefault = false //
)
public class MapSectionsDebuggerBot extends AbstractMapDebuggerBot {

	@Override
	protected Collection<TraceChangeType<?, ?>> getChangeTypes() {
		return List.of(TraceSectionChangeType.ADDED);
	}

	@Override
	protected void doAnalysis(PluginTool tool,
							  Trace trace,
							  Set<Program> programs,
							  TaskMonitor monitor
	) throws CancelledException {
		Optional<DebuggerStaticMappingService> debuggerStaticMappingServiceOptional = tool.getService(
				DebuggerStaticMappingService.class
		);
		if (debuggerStaticMappingServiceOptional.isPresent()) {
			DebuggerStaticMappingService debuggerStaticMappingService = debuggerStaticMappingServiceOptional.get();
			Map<?, SectionMapProposal> maps = debuggerStaticMappingService.proposeSectionMaps(
					trace.getModuleManager().getAllModules(), programs
			);
			Collection<SectionMapEntry> entries = MapProposal.removeOverlapping(
					MapProposal.flatten(maps.values())
			);
			debuggerStaticMappingService.addSectionMappings(entries, monitor, false);
		}
	}

}
