from PySide6.QtCore import Signal
from PySide6.QtGui import QColor, QFontDatabase, QTextCursor, QTextFormat
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

class HexView(QWidget):
    read_failed = Signal(str)
    PAGE_SIZE = 256
    BYTES_PER_ROW = 16

    def __init__(
        self,
        read_at,
        size_of,
        parent = None,
    ):
        super().__init__(parent)
        self._read_at = read_at
        self._size_of = size_of
        self._source_id = None
        self.page_start = 0
        self._ranges = ()
        self._highlight = False

        self.previous_button = QPushButton("Previous page", self)
        self.next_button = QPushButton("Next page", self)
        self.page_label = QLabel("No bytes", self)
        self.editor = QPlainTextEdit(self)
        self.editor.setReadOnly(True)
        self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.editor.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))

        controls = QHBoxLayout()
        controls.addWidget(self.previous_button)
        controls.addWidget(self.page_label, 1)
        controls.addWidget(self.next_button)
        layout = QVBoxLayout(self)
        layout.addLayout(controls)
        layout.addWidget(self.editor)
        self.previous_button.clicked.connect(self.previous_page)
        self.next_button.clicked.connect(self.next_page)
        self.clear()

    def clear(self):
        self._source_id = None
        self.page_start = 0
        self._ranges = ()
        self._highlight = False
        self.editor.clear()
        self.editor.setExtraSelections([])
        self.page_label.setText("No bytes")
        self.previous_button.setEnabled(False)
        self.next_button.setEnabled(False)

    def clear_highlight(self):
        self._ranges = ()
        self._highlight = False
        self.editor.setExtraSelections([])

    def show_ranges(
        self, ranges, *, highlight = False
    ):
        if not ranges:
            self.clear()
            return True
        first = ranges[0]
        self._source_id = first.source_id
        self.page_start = (first.offset // self.PAGE_SIZE) * self.PAGE_SIZE
        self._ranges = ranges
        self._highlight = highlight
        return self._render_page()

    def previous_page(self):
        if self._source_id is not None and self.page_start > 0:
            self.page_start -= self.PAGE_SIZE
            self._render_page()

    def next_page(self):
        if self._source_id is None:
            return
        try:
            size = self._size_of(self._source_id)
        except (OSError, EOFError, ValueError, KeyError) as exc:
            self._display_read_error(exc)
            return
        if self.page_start + self.PAGE_SIZE < size:
            self.page_start += self.PAGE_SIZE
            self._render_page()

    def _render_page(self):
        assert self._source_id is not None
        try:
            size = self._size_of(self._source_id)
            if any(span.source_id != self._source_id for span in self._ranges):
                raise ValueError("ranges from different sources cannot share one HEX view")
            if any(
                span.offset + span.length > size
                for span in self._ranges
            ):
                raise ValueError("display range exceeds image size")
            length = min(self.PAGE_SIZE, max(0, size - self.page_start))
            data = self._read_at(self._source_id, self.page_start, length)
            if len(data) != length:
                raise EOFError(
                    f"short read at offset {self.page_start}: "
                    f"requested {length} bytes, got {len(data)}"
                )
        except (OSError, EOFError, ValueError, KeyError) as exc:
            self._display_read_error(exc)
            return False
        lines = []
        positions = {}
        text_start = 0
        for index in range(0, len(data), self.BYTES_PER_ROW):
            row = data[index : index + self.BYTES_PER_ROW]
            absolute = self.page_start + index
            prefix = f"{absolute:016X}  "
            hex_part = " ".join(f"{byte:02X}" for byte in row).ljust(47)
            ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in row)
            line = f"{prefix}{hex_part}  |{ascii_part}|"
            lines.append(line)
            ascii_start = text_start + len(prefix) + len(hex_part) + 3
            for column in range(len(row)):
                positions[absolute + column] = (
                    text_start + len(prefix) + column * 3,
                    ascii_start + column,
                )
            text_start += len(line) + 1

        self.editor.setPlainText("\n".join(lines))
        self.page_label.setText(
            f"{self._source_id}: 0x{self.page_start:X}–0x{self.page_start + length:X} "
            f"of 0x{size:X}"
        )
        self.previous_button.setEnabled(self.page_start > 0)
        self.next_button.setEnabled(self.page_start + self.PAGE_SIZE < size)

        selections = []
        if self._highlight:
            for span in self._ranges:
                if span.source_id != self._source_id:
                    continue
                start = max(span.offset, self.page_start)
                end = min(span.offset + span.length, self.page_start + len(data))
                for byte_offset in range(start, end):
                    if byte_offset not in positions:
                        continue
                    hex_pos, ascii_pos = positions[byte_offset]
                    for position, width in ((hex_pos, 2), (ascii_pos, 1)):
                        selection = QTextEdit.ExtraSelection()
                        cursor = self.editor.textCursor()
                        cursor.setPosition(position)
                        cursor.setPosition(position + width, QTextCursor.MoveMode.KeepAnchor)
                        selection.cursor = cursor
                        selection.format.setBackground(QColor("#FFD36E"))
                        selection.format.setProperty(QTextFormat.Property.FullWidthSelection, False)
                        selections.append(selection)
        self.editor.setExtraSelections(selections)
        cursor = self.editor.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.editor.setTextCursor(cursor)
        return True

    def _display_read_error(self, exc):
        message = f"Cannot read image bytes at 0x{self.page_start:X}: {exc}"
        self.clear()
        self.read_failed.emit(message)
