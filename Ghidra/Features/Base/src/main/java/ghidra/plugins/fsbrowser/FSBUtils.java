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
package ghidra.plugins.fsbrowser;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import docking.widgets.SelectFromListDialog;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.Option;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

import javax.annotation.Nullable;

/**
 * {@link FileSystemBrowserPlugin} utility methods that other things might find useful.
 */
public class FSBUtils {

    /**
     * Returns the {@link ProgramManager} associated with this fs browser plugin.
     * <p>
     * When this FS Browser plugin is part of the front-end tool, this will search
     * for an open CodeBrowser tool that can be used to handle programs.
     * <p>
     * When this FS Browser plugin is part of a CodeBrowser tool, this will just return
     * the local ProgramManager / CodeBrowser.
     *
     * @param tool            The plugin tool.
     * @param allowUserPrompt boolean flag to allow this method to query the user to select
     *                        a CodeBrowser.
     * @return null if front-end and no open CodeBrowser, otherwise returns the local
     * CodeBrowser ProgramManager service.
     */
    @Nullable
    public static ProgramManager getProgramManager(PluginTool tool, boolean allowUserPrompt) {
        Optional<ProgramManager> programManagerOptional = tool.getService(ProgramManager.class);
        if (programManagerOptional.isPresent()) {
            return tool.getService(ProgramManager.class).orElse(null);
        }
        List<PluginTool> runningPMTools = FSBUtils.getRunningProgramManagerTools(tool);
        Optional<PluginTool> pluginTool = Optional.empty();
        if (runningPMTools.size() == 1) {
            pluginTool = Optional.ofNullable(runningPMTools.get(0));
        }
        if (allowUserPrompt) {
            pluginTool = Optional.ofNullable(selectPMTool(tool));
        }
        return pluginTool.flatMap(pm -> pm.getService(ProgramManager.class)).orElse(null);
    }

    public static List<PluginTool> getRunningProgramManagerTools(PluginTool tool) {
        List<PluginTool> pluginTools = new ArrayList<>();
        Arrays.stream(tool.getToolServices().getRunningTools()).forEach(runningTool -> {
            Optional<ProgramManager> pmService = runningTool.getService(ProgramManager.class);
            if (pmService.isPresent()) {
                pluginTools.add(runningTool);
            }
        });
        return pluginTools;
    }

    private static PluginTool selectPMTool(PluginTool tool) {
        if (tool.getService(ProgramManager.class).isEmpty()) {
            return tool;
        }

        List<PluginTool> pluginTools = FSBUtils.getRunningProgramManagerTools(tool);

        if (pluginTools.size() == 1) {
            return pluginTools.get(0);
        }

        if (pluginTools.isEmpty()) {
            Msg.showWarn(tool, tool.getActiveWindow(), "No open tools",
                    "There are no open tools to use to open a program with");
            return null;
        }

        return SelectFromListDialog.selectFromList(pluginTools, "Select tool",
                "Select a tool to use to open programs", pluginTool -> pluginTool.getName());
    }

}
