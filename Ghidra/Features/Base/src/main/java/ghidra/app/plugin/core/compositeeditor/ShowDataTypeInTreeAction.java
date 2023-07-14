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
package ghidra.app.plugin.core.compositeeditor;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.ToolBarData;
import generic.theme.GIcon;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.*;

/**
 * Shows the editor's data type in the UI using the {@link DataTypeManagerService}.
 */
public class ShowDataTypeInTreeAction extends CompositeEditorTableAction {

	// This action should go after the row-based actions, which have this group:
	// 3_COMPONENT_EDITOR_ACTION
	private static final String TOOLBAR_GROUP = "4_COMPONENT_EDITOR_ACTION";
	private static final Icon ICON = new GIcon("icon.plugin.composite.editor.show.type");

	public ShowDataTypeInTreeAction(CompositeEditorProvider provider) {
		super(provider, "Show In Data Type Manager", TOOLBAR_GROUP, null /*popupPath*/,
			null /*menuPath*/, ICON);

		setToolBarData(new ToolBarData(ICON, TOOLBAR_GROUP));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		tool.getService(DataTypeManagerService.class).ifPresent(service -> {
			DataTypeManager dtm = provider.getDataTypeManager();
			DataTypePath path = provider.getDtPath();
			DataType dt = dtm.getDataType(path);
			service.setDataTypeSelected(dt);
		});
	}

	@Override
	public void adjustEnablement() {
		DataTypeManager dtm = provider.getDataTypeManager();
		DataTypePath path = provider.getDtPath();
		DataType dt = dtm.getDataType(path);
		setEnabled(dt != null);
	}
}
