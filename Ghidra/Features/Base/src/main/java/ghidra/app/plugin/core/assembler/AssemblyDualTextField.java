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
package ghidra.app.plugin.core.assembler;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.text.BadLocationException;

import docking.EmptyBorderToggleButton;
import docking.widgets.autocomplete.*;
import docking.widgets.label.GDLabel;
import docking.widgets.textfield.TextFieldLinker;
import generic.theme.GColor;
import generic.theme.GIcon;
import generic.theme.GThemeDefaults.Colors;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseErrorResult;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.processors.sleigh.*;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Instruction;
import ghidra.util.NumericUtilities;

/**
 * A pair of text fields suitable for guided assembly
 * 
 * <p>
 * This object must be updated with program location information, so that it knows the applicable
 * language and address. It then provides two text boxes: one for the mnemonic, and one for the
 * operands. The two are linked so that the user can intuitively navigate between them as if they
 * were a single text box. The boxes are also attached to an autocompleter. It provides suggestions
 * based syntax errors returned by the assembler. When a valid instruction is present, it provides
 * the resulting instruction bytes.
 * 
 * <p>
 * To detect when the user has activated an instruction-bytes entry, add an
 * {@link AutocompletionListener} and check that the selection is an {@link AssemblyInstruction}.
 * Otherwise, the usual autocompletion behavior is applied automatically.
 */
public class AssemblyDualTextField {

	private static Color FG_PREFERENCE_MOST =
		new GColor("color.fg.plugin.assembler.completion.most");
	private static Color FG_PREFERENCE_MIDDLE =
		new GColor("color.fg.plugin.assembler.completion.middle");
	private static Color FG_PREFERENCE_LEAST =
		new GColor("color.fg.plugin.assembler.completion.least");

	protected final TextFieldLinker linker = new TextFieldLinker();
	protected final JTextField mnemonic = new JTextField();
	protected final JTextField operands = new JTextField();
	protected final JTextField assembly = new JTextField();

	protected final AssemblyAutocompletionModel model = new AssemblyAutocompletionModel();
	protected final AssemblyAutocompleter auto = new AssemblyAutocompleter(model);

	protected Assembler assembler;
	protected Address address;
	protected Instruction existing;
	protected boolean exhaustUndefined = false;

	/**
	 * A generic class for all items listed by the autocompleter
	 */
	public static class AssemblyCompletion implements Comparable<AssemblyCompletion> {
		private final String text;
		private final String display;
		private final Color color;
		protected int order;

		public AssemblyCompletion(String text, String display, Color color, int order) {
			this.text = text;
			this.display = display;
			this.color = color;
			this.order = order;
		}

		/**
		 * Get the foreground color for the item
		 * 
		 * @return the color
		 */
		public Color getColor() {
			return color;
		}

		/**
		 * Get the (possibly HTML) text to display for the item
		 * 
		 * @return the text
		 */
		public String getDisplay() {
			return display;
		}

		/**
		 * Get the text to insert when the item is activated
		 * 
		 * @return the text
		 */
		public String getText() {
			return text;
		}

		/**
		 * Override this to permit activation by default, i.e., on CTRL-SPACE
		 * 
		 * @return true to permit defaulting, false to prevent it
		 */
		public boolean getCanDefault() {
			return false;
		}

		@Override
		public String toString() {
			return getDisplay();
		}

		@Override
		public boolean equals(Object o) {
			if (!(o instanceof AssemblyCompletion)) {
				return false;
			}
			return this.toString().equals(o.toString());
		}

		@Override
		public int hashCode() {
			return this.toString().hashCode();
		}

		@Override
		public int compareTo(AssemblyCompletion that) {
			if (this.order != that.order) {
				return this.order - that.order;
			}
			return this.toString().compareTo(that.toString());
		}
	}

	/**
	 * Represents a textual suggestion to complete or partially complete an assembly instruction
	 */
	static class AssemblySuggestion extends AssemblyCompletion {
		public AssemblySuggestion(String text, String display) {
			super(text, display, null, 1);
		}

		@Override
		public boolean getCanDefault() {
			return true;
		}
	}

	/**
	 * Represents an encoding for a complete assembly instruction
	 * 
	 * <p>
	 * These provide no insertion text, since their activation should be handled by a custom
	 * listener.
	 */
	static class AssemblyInstruction extends AssemblyCompletion {
		private byte[] data;

		public AssemblyInstruction(String text, byte[] data, int preference) {
			// TODO?: Description to display constructor tree information
			super("", NumericUtilities.convertBytesToString(data, " "),
				preference == 10000 ? FG_PREFERENCE_MOST
						: preference == 5000 ? FG_PREFERENCE_MIDDLE : FG_PREFERENCE_LEAST,
				-preference);
			this.data = data;
		}

		/**
		 * Get the assembled instruction bytes
		 * 
		 * @return the bytes
		 */
		public byte[] getData() {
			return data;
		}

		@Override
		public int compareTo(AssemblyCompletion ac) {
			if (this.order != ac.order) {
				return this.order - ac.order;
			}
			if (!(ac instanceof AssemblyInstruction)) {
				return super.compareTo(ac);
			}
			AssemblyInstruction that = (AssemblyInstruction) ac;
			if (this.data.length != that.data.length) {
				return this.data.length - that.data.length;
			}
			return super.compareTo(ac);
		}
	}

	/**
	 * Represents the description of an error encountered during parsing or assembling
	 * 
	 * <p>
	 * <b>NOTE:</b> not used until error descriptions improve
	 */
	static class AssemblyError extends AssemblyCompletion {
		private String text;

		public AssemblyError(String text, String desc) {
			super(text, desc, Colors.ERROR, 1);
			this.text = text;
		}

		@Override
		public String getText() {
			return text;
		}
	}

	/**
	 * A model that just delegates to our completion function
	 */
	class AssemblyAutocompletionModel implements AutocompletionModel<AssemblyCompletion> {
		@Override
		public Collection<AssemblyCompletion> computeCompletions(String text) {
			return AssemblyDualTextField.this.computeCompletions(text);
		}
	}

	/**
	 * A customized autocompleter for assembly
	 * 
	 * <p>
	 * This positions the list at the bottom left of the field(s), and considers the full text of
	 * the linked text boxes when retrieving the prefix. It also delegates the item styling to the
	 * item instances.
	 */
	class AssemblyAutocompleter extends TextFieldAutocompleter<AssemblyCompletion> {
		public AssemblyAutocompleter(AutocompletionModel<AssemblyCompletion> model) {
			super(model);
		}

		void fakeFocusGained(JTextField field) {
			listener.fakeFocusGained(field);
		}

		@Override
		protected String getPrefix(JTextField field) {
			if (field == assembly) {
				return field.getText().substring(0, field.getCaretPosition());
			}
			return linker.getTextBeforeCursor(field);
		}

		@Override
		protected String getCompletionDisplay(AssemblyCompletion sel) {
			return sel.getDisplay();
		}

		@Override
		protected Color getCompletionForeground(AssemblyCompletion sel, boolean isSelected,
				boolean cellHasFocus) {
			if (!isSelected) {
				return sel.getColor();
			}
			return null;
		}

		@Override
		protected String getCompletionText(AssemblyCompletion sel) {
			return sel.getText();
		}

		@Override
		protected boolean getCompletionCanDefault(AssemblyCompletion sel) {
			return sel.getCanDefault();
		}

		@Override
		protected Point getCompletionWindowPosition() {
			if (assembly.isVisible()) {
				Point p = new Point(0, assembly.getHeight());
				SwingUtilities.convertPointToScreen(p, assembly);
				return p;
			}
			Point p = new Point(0, 0);
			SwingUtilities.convertPointToScreen(p, mnemonic);
			Point q = new Point(0, linker.getFocusedField().getHeight());
			SwingUtilities.convertPointToScreen(q, linker.getFocusedField());
			p.y = q.y;
			return p;
		}

		@Override
		protected Dimension getDefaultCompletionWindowDimension() {
			int width = 0;
			if (assembly.isVisible()) {
				width = assembly.getWidth();
			}
			else {
				Point p = new Point(0, 0);
				SwingUtilities.convertPointToScreen(p, mnemonic);
				Point q = new Point(operands.getWidth(), 0);
				SwingUtilities.convertPointToScreen(q, operands);
				width = q.x - p.x;
			}
			return new Dimension(width, -1);
		}

		private static final String CMD_EXHAUST = "Exhaust undefined bits";
		private static final String CMD_ZERO = "Zero undefined bits";

		@Override
		protected void addContent(JPanel content) {
			Box controls = Box.createHorizontalBox();
			Icon icon = new GIcon("icon.plugin.assembler.question");
			EmptyBorderToggleButton button = new EmptyBorderToggleButton(icon);
			button.setToolTipText("Exhaust unspecified bits, otherwise zero them");
			button.addActionListener((e) -> {
				exhaustUndefined = CMD_EXHAUST.equals(e.getActionCommand());
				if (exhaustUndefined) {
					button.setActionCommand(CMD_ZERO);
				}
				else {
					button.setActionCommand(CMD_EXHAUST);
				}
				auto.updateDisplayContents();
			});
			button.setActionCommand(CMD_EXHAUST);
			controls.add(button);
			content.add(controls, BorderLayout.SOUTH);
		}

	}

	/**
	 * A listener which activates the autocompleter on ENTER (in addition to the default
	 * CTRL-SPACE).
	 * 
	 * <p>
	 * Because the user must activate an entry to specify the desired assembly, we make ENTER pull
	 * up the list, hinting that the user must make a selection.
	 */
	class EnterKeyListener implements KeyListener {
		@Override
		public void keyTyped(KeyEvent e) {
			if (e.getKeyChar() != KeyEvent.VK_ESCAPE) {
				auto.setCompletionListVisible(true);
			}
		}

		@Override
		public void keyPressed(KeyEvent e) {
			if (e.isConsumed()) {
				return;
			}
			if (e.getKeyCode() == KeyEvent.VK_ENTER) {
				if (!auto.isCompletionListVisible()) {
					auto.startCompletion((JTextField) e.getComponent());
					e.consume();
				}
			}
		}

		@Override
		public void keyReleased(KeyEvent e) {
			// Blank
		}
	}

	/**
	 * Construct the assembly text fields
	 */
	public AssemblyDualTextField() {
		// Because the option must actually be selected from the list, cause the enter key to show
		// the completions.
		KeyListener kl = new EnterKeyListener();

		// Configure the linked fields
		linker.linkField(mnemonic, "\\s+", " ");
		auto.attachTo(mnemonic);
		mnemonic.addKeyListener(kl);
		configureField(mnemonic);
		mnemonic.setName("AssemblerMnemonic");

		linker.linkLastField(operands);
		auto.attachTo(operands);
		operands.addKeyListener(kl);
		configureField(operands);
		operands.setName("AssemblerOperands");
		operands.setFocusTraversalKeysEnabled(false);

		// Configure the unlinked variant
		auto.attachTo(assembly);
		assembly.addKeyListener(kl);
		configureField(assembly);
		assembly.setName("AssemblerSingleField");
		assembly.setFocusTraversalKeysEnabled(false);
	}

	void dispose() {
		auto.dispose();
	}

	/**
	 * Set the assembler to use
	 * 
	 * @param assembler the assembler
	 */
	public void setAssembler(Assembler assembler) {
		this.assembler = Objects.requireNonNull(assembler);
	}

	/**
	 * Set the address of the assembly instruction
	 * 
	 * <p>
	 * Note this will reset the existing instruction to null to prevent its accidental re-use. See
	 * {@link #setExisting(Instruction)}.
	 * 
	 * @param address the address
	 */
	public void setAddress(Address address) {
		this.address = Objects.requireNonNull(address);
		this.existing = null;
	}

	/**
	 * Set the "existing" instruction used for ordering proposed instructions by "most similar"
	 * 
	 * @see #computePreference(AssemblyResolvedPatterns)
	 * @param existing the existing instruction
	 */
	public void setExisting(Instruction existing) {
		this.existing = existing;
	}

	/**
	 * For dual mode: Get the text field containing the mnemonic portion of the assembly
	 * 
	 * @return the text field
	 */
	public JTextField getMnemonicField() {
		return mnemonic;
	}

	/**
	 * For dual mode: Get the text field containing the operands portion of the assembly
	 * 
	 * @return the text field
	 */
	public JTextField getOperandsField() {
		return operands;
	}

	/**
	 * For single mode: Get the text field containing the full assembly text
	 * @return the text field
	 */
	public JTextField getAssemblyField() {
		return assembly;
	}

	/**
	 * Get a reference to the autocompleter
	 * 
	 * <p>
	 * This is useful for adding the custom listener needed to detect activation of assembled
	 * instruction entries.
	 * 
	 * @return the autocompleter
	 */
	public TextFieldAutocompleter<AssemblyCompletion> getAutocompleter() {
		return auto;
	}

	/**
	 * Clear all text boxes
	 */
	public void clear() {
		linker.clear();
		assembly.setText("");
	}

	/**
	 * An enum type to specify which variant of the assembly input is shown.
	 */
	public enum VisibilityMode {
		/**
		 * Hide both variants. Nothing is shown.
		 */
		INVISIBLE,
		/**
		 * Show the dual-box linked variant, suitable when the current instruction has operands.
		 */
		DUAL_VISIBLE,
		/**
		 * Show the single-box unlinked variant, suitable when the current instruction has no
		 * operands.
		 */
		SINGLE_VISIBLE;
	}

	/**
	 * Set the visibility of the text box(es)
	 * 
	 * @param visibility the {@link VisibilityMode} to set.
	 */
	public void setVisible(VisibilityMode visibility) {
		switch (visibility) {
			case INVISIBLE:
				linker.setVisible(false);
				assembly.setVisible(false);
				break;
			case DUAL_VISIBLE:
				linker.setVisible(true);
				assembly.setVisible(false);
				break;
			case SINGLE_VISIBLE:
				linker.setVisible(false);
				assembly.setVisible(true);
				break;
		}
	}

	/**
	 * Get the visibility of the text box(es)
	 * 
	 * <p>
	 * <b>NOTE:</b> This method assumes nothing else changes the visibility of the text boxes. If
	 * anything else does, then it should be sure to maintain a configuration consistent with one of
	 * the {@link VisibilityMode}s.
	 * 
	 * @return the current mode
	 */
	public VisibilityMode getVisible() {
		if (linker.isVisible()) {
			if (assembly.isVisible()) {
				throw new AssertionError();
			}
			return VisibilityMode.DUAL_VISIBLE;
		}

		if (assembly.isVisible()) {
			return VisibilityMode.SINGLE_VISIBLE;
		}
		return VisibilityMode.INVISIBLE;
	}

	/**
	 * Set the font for all text fields
	 * 
	 * @param font the new font
	 */
	public void setFont(Font font) {
		linker.setFont(font);
		assembly.setFont(font);
	}

	/**
	 * Add a focus listener to the box(es)
	 * 
	 * <p>
	 * <b>NOTE:</b> The listener will not fire when focus passes among the linked boxes of the dual
	 * variant.
	 * 
	 * @param listener the listener
	 */
	public void addFocusListener(FocusListener listener) {
		linker.addFocusListener(listener);
		assembly.addFocusListener(listener);
	}

	/**
	 * Add a key listener to the box(es)
	 * 
	 * @param listener the listener
	 */
	public void addKeyListener(KeyListener listener) {
		mnemonic.addKeyListener(listener);
		operands.addKeyListener(listener);
		assembly.addKeyListener(listener);
	}

	/**
	 * Get the full assembly text
	 * 
	 * @return the text
	 */
	public String getText() {
		if (assembly.isVisible()) {
			return assembly.getText();
		}
		return linker.getText();
	}

	/**
	 * Set the text of the visible field(s)
	 * 
	 * @param text the text
	 */
	public void setText(String text) {
		if (assembly.isVisible()) {
			assembly.setText(text);
		}
		else {
			linker.setText(text);
		}
	}

	/**
	 * Set the caret position of the visible field(s)
	 * 
	 * @param pos the position
	 */
	public void setCaretPosition(int pos) {
		try {
			if (assembly.isVisible()) {
				assembly.setCaretPosition(pos);
			}
			else {
				linker.setCaretPosition(pos);
			}
		}
		catch (BadLocationException e) {
			assert false;
		}
	}

	/**
	 * Sets the style of the text fields
	 * 
	 * <p>
	 * This is an extension point.
	 * 
	 * @param field the field to configure
	 */
	protected void configureField(JTextField field) {
		Font mono = new Font(Font.MONOSPACED, Font.PLAIN, 12); // TODO: Font size from options
		field.setFont(mono);
	}

	/**
	 * Construct the HTML display for a given suggestion
	 *
	 * <p>
	 * This is an extension point.
	 * 
	 * <p>
	 * Currently, this just shows the current prefix in bold, and the text that would be inserted as
	 * normal weight.
	 * 
	 * @param prefix the text currently in the fields
	 * @param suggestion the text suggested by the assembly syntax analyzer
	 * @param bufferleft the portion of the prefix that is also part of the suggestion
	 * @return a formatted string that hints to the effect of selecting this suggestion
	 */
	protected String formatSuggestion(String prefix, String suggestion, String bufferleft) {
		String extra = suggestion.substring(bufferleft.length());
		String before = prefix.substring(0, prefix.length() - bufferleft.length());
		return String.format("<html><b>%s%s</b>%s</html>", before, bufferleft, extra);
	}

	/**
	 * Provides an ordering for assembled instructions appearing in the list
	 * 
	 * <p>
	 * The items with the highest preference are positioned at the top of the list
	 * 
	 * <p>
	 * This is an extension point.
	 * 
	 * <p>
	 * Currently, a proposed instruction having the same constructor tree as the existing one is the
	 * most preferred. Second, are instructions having a similar tree as the existing one --
	 * "similar" is not yet well defined, but at the moment, it means their constructor tree strings
	 * have a long common prefix. Third, instructions having the same encoded length as the existing
	 * one are preferred. Last, the shortest instructions are preferred.
	 * 
	 * @param rc a resolved instruction
	 * @return a preference
	 */
	protected int computePreference(AssemblyResolvedPatterns rc) {
		if (existing == null) {
			return 0;
		}
		String myTree = rc.dumpConstructorTree();
		String exTree =
			((SleighInstructionPrototype) existing.getPrototype()).dumpConstructorTree();
		for (int i = 0; i < myTree.length(); i++) {
			if (!myTree.startsWith(exTree.substring(0, i))) {
				return rc.getInstructionLength() == existing.getLength() ? 5000 : i;
			}
		}
		return 10000;
	}

	/**
	 * Compute valid completions given the prefix
	 * 
	 * <p>
	 * This is an extension point.
	 * 
	 * <p>
	 * If text parses and assembles, then the completion set will include assembled instruction-byte
	 * entries. Note that there may still be valid textual completions to continue the instruction.
	 * The suggestions yielded by all syntax errors are used to create textual completions. If the
	 * suggestion is prefixed by the buffer where the syntax error occurred, then, the tail of that
	 * suggestion is made into a completion entry.
	 * 
	 * @param text the prefix
	 * @return the collection of completion items
	 */
	protected Collection<AssemblyCompletion> computeCompletions(String text) {
		final AssemblyPatternBlock ctx = Objects.requireNonNull(getContext());

		Set<AssemblyCompletion> result = new TreeSet<>();
		Collection<AssemblyParseResult> parses = assembler.parseLine(text);
		for (AssemblyParseResult parse : parses) {
			if (parse.isError()) {
				AssemblyParseErrorResult err = (AssemblyParseErrorResult) parse;
				String buffer = err.getBuffer();
				for (String s : err.getSuggestions()) {
					if (s.startsWith(buffer)) {
						result.add(new AssemblySuggestion(s.substring(buffer.length()),
							formatSuggestion(text, s, buffer)));
					}
				}
			}
		}
		// HACK (Sort of): circumvents the API to get full text.
		String fullText = getText();
		parses = assembler.parseLine(fullText);
		for (AssemblyParseResult parse : parses) {
			if (!parse.isError()) {
				AssemblyResolutionResults sems =
					assembler.resolveTree(parse, address, ctx);
				for (AssemblyResolution ar : sems) {
					if (ar.isError()) {
						//result.add(new AssemblyError("", ar.toString()));
						continue;
					}
					AssemblyResolvedPatterns rc = (AssemblyResolvedPatterns) ar;
					for (byte[] ins : rc.possibleInsVals(ctx)) {
						result.add(new AssemblyInstruction(text, Arrays.copyOf(ins, ins.length),
							computePreference(rc)));
						if (!exhaustUndefined) {
							break;
						}
					}
				}
			}
		}
		if (result.isEmpty()) {
			result.add(new AssemblyError("", "Invalid instruction and/or prefix"));
		}
		return result;
	}

	/**
	 * Get the context for filtering completed instructions in the auto-completer
	 * 
	 * @return the context
	 */
	protected AssemblyPatternBlock getContext() {
		return assembler.getContextAt(address).fillMask();
	}

	/**
	 * A demonstration of the assembly GUI outside of Ghidra
	 */
	public class AssemblyDualTextFieldDemo implements GhidraLaunchable {
		public final LanguageID DEMO_LANG_ID = new LanguageID("x86:LE:64:default");
		public final String ADDR_FORMAT = "@%08x:";
		Address curAddr;

		@Override
		public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
			Application.initializeApplication(layout, new ApplicationConfiguration());
			JDialog dialog = new JDialog((Window) null, "Assembly Autocompleter Demo");

			dialog.setLayout(new BorderLayout());

			Box hbox = Box.createHorizontalBox();
			dialog.add(hbox, BorderLayout.NORTH);

			JLabel addrlabel = new GDLabel(String.format(ADDR_FORMAT, curAddr));
			hbox.add(addrlabel);

			AssemblyDualTextField input = new AssemblyDualTextField();

			SleighLanguageProvider provider = new SleighLanguageProvider();
			SleighLanguage lang = (SleighLanguage) provider.getLanguage(DEMO_LANG_ID);
			curAddr = lang.getDefaultSpace().getAddress(0);

			input.setAssembler(Assemblers.getAssembler(lang));
			input.setAddress(curAddr);

			hbox.add(input.getAssemblyField());
			hbox.add(input.getMnemonicField());
			hbox.add(Box.createHorizontalStrut(10));
			hbox.add(input.getOperandsField());

			JTextArea asm = new JTextArea();
			asm.setEditable(false);
			asm.setLineWrap(true);
			asm.setWrapStyleWord(false);
			dialog.add(asm, BorderLayout.CENTER);

			input.getAutocompleter().addAutocompletionListener(e -> {
				if (e.getSelection() instanceof AssemblyInstruction) {
					AssemblyInstruction ins = (AssemblyInstruction) e.getSelection();
					String data = NumericUtilities.convertBytesToString(ins.getData());
					asm.setText(asm.getText() + data);
					input.clear();
					curAddr = curAddr.addWrap(ins.getData().length);
					input.setAddress(curAddr);
					addrlabel.setText(String.format(ADDR_FORMAT, curAddr));
				}
			});

			AtomicReference<VisibilityMode> vis =
				new AtomicReference<>(VisibilityMode.DUAL_VISIBLE);
			input.setVisible(vis.get());
			KeyListener l = new KeyListener() {
				@Override
				public void keyTyped(KeyEvent e) {
					// NOTHING
				}

				@Override
				public void keyPressed(KeyEvent e) {
					if (e.isAltDown() && e.isShiftDown() && e.getKeyChar() == KeyEvent.VK_D) {
						if (vis.get() == VisibilityMode.DUAL_VISIBLE) {
							vis.set(VisibilityMode.SINGLE_VISIBLE);
						}
						else {
							vis.set(VisibilityMode.DUAL_VISIBLE);
						}
						input.setVisible(vis.get());
						dialog.validate();
					}
				}

				@Override
				public void keyReleased(KeyEvent e) {
					// NOTHING
				}
			};
			input.addKeyListener(l);

			asm.setVisible(true);

			dialog.setBounds(2560, 500, 400, 200);
			dialog.setModal(true);
			dialog.setVisible(true);
		}
	}
}
