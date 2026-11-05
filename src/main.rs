#![windows_subsystem = "windows"]

use eframe::egui;
use egui::emath::GuiRounding;
use egui::{
    pos2, vec2, Align2, Color32, FontData, FontDefinitions, FontFamily, FontId, Rect, RichText,
    Sense, Stroke, Vec2,
};
use std::sync::Arc;
use std::fs;
use std::path::{Path, PathBuf};

const OLD: &[u8] = b"( %g %g %g ) ( %g %g %g ) ( %g %g %g )\0";
const NEW: &[u8] = b"( %.9g %.9g %.9g ) ( %.9g %.9g %.9g ) ( %.9g %.9g %.9g )\0";
const DLL: &str = "vpHalfLifex64.dll";

struct Section {
    name: String,
    header: usize,
    va: u32,
    vsize: u32,
    raw: u32,
    rawsize: u32,
}

struct Pe {
    sections: Vec<Section>,
}

fn u16_at(d: &[u8], o: usize) -> Result<u16, String> {
    d.get(o..o + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| "truncated file".into())
}

fn u32_at(d: &[u8], o: usize) -> Result<u32, String> {
    d.get(o..o + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| "truncated file".into())
}

impl Pe {
    fn parse(d: &[u8]) -> Result<Pe, String> {
        if d.get(0..2) != Some(b"MZ") {
            return Err("not a PE file".into());
        }
        let pe = u32_at(d, 0x3c)? as usize;
        if d.get(pe..pe + 4) != Some(b"PE\0\0") {
            return Err("not a PE file".into());
        }
        if u16_at(d, pe + 4)? != 0x8664 {
            return Err("not a 64-bit DLL".into());
        }
        let count = u16_at(d, pe + 6)? as usize;
        let opt = u16_at(d, pe + 20)? as usize;
        let first = pe + 24 + opt;
        let mut sections = Vec::new();
        for i in 0..count {
            let h = first + i * 40;
            let raw_name = d.get(h..h + 8).ok_or("truncated file")?;
            let name = String::from_utf8_lossy(raw_name)
                .trim_end_matches('\0')
                .to_string();
            sections.push(Section {
                name,
                header: h,
                vsize: u32_at(d, h + 8)?,
                va: u32_at(d, h + 12)?,
                rawsize: u32_at(d, h + 16)?,
                raw: u32_at(d, h + 20)?,
            });
        }
        Ok(Pe { sections })
    }

    fn section(&self, name: &str) -> Result<&Section, String> {
        self.sections
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| format!("no {name} section"))
    }

    fn off_to_rva(&self, off: usize) -> Option<u32> {
        self.sections.iter().find_map(|s| {
            let o = off as u32;
            (o >= s.raw && o < s.raw + s.rawsize).then(|| o - s.raw + s.va)
        })
    }
}

fn find_all(d: &[u8], pat: &[u8]) -> Vec<usize> {
    d.windows(pat.len())
        .enumerate()
        .filter(|(_, w)| *w == pat)
        .map(|(i, _)| i)
        .collect()
}

fn lea_refs(d: &[u8], pe: &Pe, target: u32) -> Result<Vec<usize>, String> {
    let t = pe.section(".text")?;
    let start = t.raw as usize;
    let end = (t.raw + t.rawsize) as usize;
    let mut out = Vec::new();
    for i in start..end.saturating_sub(7) {
        if (d[i] == 0x48 || d[i] == 0x4c) && d[i + 1] == 0x8d && (d[i + 2] & 0xc7) == 5 {
            let disp = i32::from_le_bytes([d[i + 3], d[i + 4], d[i + 5], d[i + 6]]);
            let next = pe.off_to_rva(i).ok_or("bad offset")? as i64 + 7;
            if next + disp as i64 == target as i64 {
                out.push(i);
            }
        }
    }
    Ok(out)
}

enum State {
    Original { lea: usize, rva_new: u32, off_new: usize, vsize: u32 },
    Patched,
}

fn inspect(d: &[u8]) -> Result<State, String> {
    let pe = Pe::parse(d)?;
    let rdata = pe.section(".rdata")?;
    let lo = rdata.raw as usize;
    let hi = (rdata.raw + rdata.rawsize) as usize;

    for off in find_all(&d[lo..hi], NEW) {
        let rva = pe.off_to_rva(lo + off).ok_or("bad offset")?;
        if lea_refs(d, &pe, rva)?.len() == 1 {
            return Ok(State::Patched);
        }
    }

    let olds = find_all(&d[lo..hi], OLD);
    let old_rva = match olds.as_slice() {
        [o] => pe.off_to_rva(lo + o).ok_or("bad offset")?,
        [] => return Err("face format string not found; unknown plugin version".into()),
        _ => return Err("face format string found more than once".into()),
    };
    let leas = lea_refs(d, &pe, old_rva)?;
    let lea = match leas.as_slice() {
        [l] => *l,
        [] => return Err("no code reference to the face format string".into()),
        _ => return Err("face format string referenced more than once".into()),
    };

    let used = (rdata.vsize + 15) & !15;
    let need = used + NEW.len() as u32;
    if need > rdata.rawsize {
        return Err("not enough free space in .rdata".into());
    }
    let off_new = rdata.raw as usize + used as usize;
    let slack_from = rdata.raw as usize + rdata.vsize as usize;
    if d[slack_from..off_new + NEW.len()].iter().any(|&b| b != 0) {
        return Err(".rdata free space is not empty".into());
    }
    Ok(State::Original {
        lea,
        rva_new: rdata.va + used,
        off_new,
        vsize: need,
    })
}

fn patch(d: &mut [u8]) -> Result<(), String> {
    let State::Original { lea, rva_new, off_new, vsize } = inspect(d)? else {
        return Err("already patched".into());
    };
    let pe = Pe::parse(d)?;
    let hdr = pe.section(".rdata")?.header;
    d[off_new..off_new + NEW.len()].copy_from_slice(NEW);
    let next = pe.off_to_rva(lea).ok_or("bad offset")? as i64 + 7;
    let disp = (rva_new as i64 - next) as i32;
    d[lea + 3..lea + 7].copy_from_slice(&disp.to_le_bytes());
    d[hdr + 8..hdr + 12].copy_from_slice(&vsize.to_le_bytes());
    match inspect(d)? {
        State::Patched => Ok(()),
        State::Original { .. } => Err("patch did not verify".into()),
    }
}

fn unpatch(d: &mut [u8]) -> Result<(), String> {
    let pe = Pe::parse(d)?;
    let rdata = pe.section(".rdata")?;
    let lo = rdata.raw as usize;
    let hi = (rdata.raw + rdata.rawsize) as usize;
    let hdr = rdata.header;
    let mut found = None;
    for off in find_all(&d[lo..hi], NEW) {
        let rva = pe.off_to_rva(lo + off).ok_or("bad offset")?;
        if let [l] = lea_refs(d, &pe, rva)?.as_slice() {
            found = Some((lo + off, *l));
        }
    }
    let (off_new, lea) = found.ok_or("not patched")?;
    let used = (off_new - lo) as u32;
    if used % 16 != 0 || used + NEW.len() as u32 != rdata.vsize {
        return Err("patch layout not recognized".into());
    }
    let old_rva = match find_all(&d[lo..hi], OLD).as_slice() {
        [o] => pe.off_to_rva(lo + o).ok_or("bad offset")?,
        _ => return Err("original face format string not found".into()),
    };
    let next = pe.off_to_rva(lea).ok_or("bad offset")? as i64 + 7;
    let disp = (old_rva as i64 - next) as i32;
    d[lea + 3..lea + 7].copy_from_slice(&disp.to_le_bytes());
    d[off_new..off_new + NEW.len()].fill(0);
    d[hdr + 8..hdr + 12].copy_from_slice(&used.to_le_bytes());
    match inspect(d)? {
        State::Original { .. } => Ok(()),
        State::Patched => Err("unpatch did not verify".into()),
    }
}

fn do_unpatch(exe: &Path) -> Result<String, String> {
    let dll = dll_for(exe).ok_or_else(|| format!("plugins\\{DLL} not found next to the exe"))?;
    let mut d = fs::read(&dll).map_err(|e| format!("read failed: {e}"))?;
    unpatch(&mut d)?;
    fs::write(&dll, &d)
        .map_err(|e| format!("write failed: {e} (close JACK, or run as administrator)"))?;
    Ok("unpatched".into())
}

fn steam_libraries() -> Vec<PathBuf> {
    let mut roots = vec![
        PathBuf::from(r"C:\Program Files (x86)\Steam"),
        PathBuf::from(r"C:\Program Files\Steam"),
    ];
    let mut libs = Vec::new();
    for r in roots.drain(..) {
        let vdf = r.join(r"steamapps\libraryfolders.vdf");
        if let Ok(text) = fs::read_to_string(&vdf) {
            for line in text.lines() {
                let parts: Vec<&str> = line.split('"').collect();
                if parts.len() >= 4 && parts[1] == "path" {
                    libs.push(PathBuf::from(parts[3].replace(r"\\", r"\")));
                }
            }
        }
        libs.push(r);
    }
    for c in b'C'..=b'Z' {
        libs.push(PathBuf::from(format!(r"{}:\SteamLibrary", c as char)));
    }
    libs
}

fn find_jack() -> Option<PathBuf> {
    steam_libraries()
        .into_iter()
        .map(|l| l.join(r"steamapps\common\JACK\jack.exe"))
        .find(|p| p.is_file())
}

fn dll_for(exe: &Path) -> Option<PathBuf> {
    let dll = exe.parent()?.join("plugins").join(DLL);
    dll.is_file().then_some(dll)
}

fn backup_path(dll: &Path) -> PathBuf {
    dll.with_extension("dll.orig")
}

fn do_patch(exe: &Path) -> Result<String, String> {
    let dll = dll_for(exe).ok_or_else(|| format!("plugins\\{DLL} not found next to the exe"))?;
    let bak = backup_path(&dll);
    let mut d = fs::read(&dll).map_err(|e| format!("read failed: {e}"))?;
    if let State::Patched = inspect(&d)? {
        return Ok("already patched".into());
    }
    patch(&mut d)?;
    if !bak.exists() {
        fs::copy(&dll, &bak).map_err(|e| format!("backup failed: {e}"))?;
    }
    fs::write(&dll, &d)
        .map_err(|e| format!("write failed: {e} (close JACK, or run as administrator)"))?;
    Ok("patched: face points now use 9 significant digits".into())
}

fn do_restore(exe: &Path) -> Result<String, String> {
    let dll = dll_for(exe).ok_or_else(|| format!("plugins\\{DLL} not found next to the exe"))?;
    let bak = backup_path(&dll);
    if !bak.is_file() {
        return Err("no backup to restore".into());
    }
    fs::copy(&bak, &dll)
        .map_err(|e| format!("restore failed: {e} (close JACK, or run as administrator)"))?;
    Ok("restored original".into())
}

fn plugin_patched(exe: &Path) -> Result<bool, String> {
    let dll = dll_for(exe).ok_or_else(|| format!("plugins\\{DLL} not found next to the exe"))?;
    let d = fs::read(&dll).map_err(|e| e.to_string())?;
    Ok(matches!(inspect(&d)?, State::Patched))
}

const BG: Color32 = Color32::from_rgb(76, 88, 68);
const ENTRY_BG: Color32 = Color32::from_rgb(62, 70, 55);
const BRIGHT: Color32 = Color32::from_rgb(136, 145, 128);
const DARK: Color32 = Color32::from_rgb(40, 46, 34);
const TEXT: Color32 = Color32::from_rgb(216, 222, 211);
const DIM: Color32 = Color32::from_rgb(160, 170, 149);
const MAIZE: Color32 = Color32::from_rgb(196, 181, 80);
const SELECTION: Color32 = Color32::from_rgb(149, 136, 49);
const DISABLED: Color32 = Color32::from_rgb(117, 128, 111);
const GLYPH: Color32 = Color32::from_rgb(173, 181, 168);
const ERROR: Color32 = Color32::from_rgb(255, 51, 51);

const TITLE_H: f32 = 24.0;
const PAD: f32 = 10.0;
const BUTTON_H: f32 = 24.0;
const ENTRY_H: f32 = 22.0;
const FONT: f32 = 12.0;

fn font() -> FontId {
    FontId::proportional(FONT)
}

fn bold() -> FontId {
    FontId::new(FONT, FontFamily::Name("bold".into()))
}

fn px(ui: &egui::Ui) -> f32 {
    1.0 / ui.ctx().pixels_per_point()
}

fn snap(ui: &egui::Ui, r: Rect) -> Rect {
    r.round_to_pixels(ui.ctx().pixels_per_point())
}

fn bevel(ui: &egui::Ui, r: Rect, lit: Color32, unlit: Color32) {
    let p = ui.painter();
    let t = px(ui);
    p.rect_filled(Rect::from_min_max(r.min, pos2(r.max.x, r.min.y + t)), 0.0, lit);
    p.rect_filled(Rect::from_min_max(r.min, pos2(r.min.x + t, r.max.y)), 0.0, lit);
    p.rect_filled(Rect::from_min_max(pos2(r.min.x, r.max.y - t), r.max), 0.0, unlit);
    p.rect_filled(Rect::from_min_max(pos2(r.max.x - t, r.min.y), r.max), 0.0, unlit);
}

fn text_width(ui: &egui::Ui, s: &str) -> f32 {
    ui.painter()
        .layout_no_wrap(s.to_string(), font(), TEXT)
        .size()
        .x
}

fn button_width(ui: &egui::Ui, s: &str) -> f32 {
    (text_width(ui, s) + 24.0).max(72.0).round()
}

fn button(ui: &mut egui::Ui, s: &str, enabled: bool) -> egui::Response {
    let size = vec2(button_width(ui, s), BUTTON_H);
    let sense = if enabled { Sense::click() } else { Sense::hover() };
    let (rect, resp) = ui.allocate_exact_size(size, sense);
    let rect = snap(ui, rect);
    let down = enabled && resp.is_pointer_button_down_on();
    let p = ui.painter();
    p.rect_filled(rect, 0.0, BG);
    if down {
        bevel(ui, rect, DARK, BRIGHT);
    } else {
        bevel(ui, rect, BRIGHT, DARK);
    }
    let mut c = rect.center();
    if down {
        c += vec2(1.0, 1.0);
    }
    if enabled {
        let color = if resp.hovered() { MAIZE } else { TEXT };
        p.text(c, Align2::CENTER_CENTER, s, font(), color);
    } else {
        p.text(c + vec2(1.0, 1.0), Align2::CENTER_CENTER, s, font(), DARK);
        p.text(c, Align2::CENTER_CENTER, s, font(), DISABLED);
    }
    resp
}

fn entry(ui: &mut egui::Ui, text: &mut String, width: f32) -> egui::Response {
    let (rect, _) = ui.allocate_exact_size(vec2(width, ENTRY_H), Sense::hover());
    let rect = snap(ui, rect);
    ui.painter().rect_filled(rect, 0.0, ENTRY_BG);
    bevel(ui, rect, DARK, BRIGHT);
    ui.put(
        rect.shrink2(vec2(4.0, 2.0)),
        egui::TextEdit::singleline(text)
            .frame(egui::Frame::NONE)
            .margin(egui::Margin::symmetric(0, 2))
            .font(font())
            .text_color(TEXT)
            .hint_text(RichText::new("Path to jack.exe").font(font()).color(DISABLED))
            .desired_width(rect.width() - 8.0),
    )
}

fn title_button(ui: &mut egui::Ui, rect: Rect, close: bool) -> bool {
    let rect = snap(ui, rect);
    let resp = ui.interact(rect, ui.scope_id().with(("title", close)), Sense::click());
    let down = resp.is_pointer_button_down_on();
    if down {
        bevel(ui, rect, DARK, BRIGHT);
    } else if resp.hovered() {
        bevel(ui, rect, BRIGHT, DARK);
    }
    let color = if resp.hovered() { MAIZE } else { GLYPH };
    let stroke = Stroke::new(1.5, color);
    let c = rect.center() + if down { vec2(1.0, 1.0) } else { Vec2::ZERO };
    let p = ui.painter();
    if close {
        let d = 3.5;
        p.line_segment([c + vec2(-d, -d), c + vec2(d, d)], stroke);
        p.line_segment([c + vec2(-d, d), c + vec2(d, -d)], stroke);
    } else {
        p.line_segment([c + vec2(-4.0, 3.5), c + vec2(4.0, 3.5)], stroke);
    }
    resp.clicked()
}

fn divider(ui: &mut egui::Ui, width: f32) {
    let (rect, _) = ui.allocate_exact_size(vec2(width, 2.0), Sense::hover());
    let rect = snap(ui, rect);
    let t = px(ui);
    let p = ui.painter();
    p.rect_filled(
        Rect::from_min_max(rect.min, pos2(rect.max.x, rect.min.y + t)),
        0.0,
        DARK,
    );
    p.rect_filled(
        Rect::from_min_max(pos2(rect.min.x, rect.min.y + t), pos2(rect.max.x, rect.min.y + 2.0 * t)),
        0.0,
        BRIGHT,
    );
}

const SEG: f32 = 8.0;
const SEG_GAP: f32 = 2.0;
const FILL_SECS: f64 = 0.1;

const SEGMENTS: usize = 37;

fn bar_width() -> f32 {
    SEGMENTS as f32 * (SEG + SEG_GAP) - SEG_GAP + 6.0
}

fn progress_bar(ui: &mut egui::Ui, progress: f32, label: Option<&str>) {
    let step = SEG + SEG_GAP;
    let count = SEGMENTS;
    let (rect, _) = ui.allocate_exact_size(vec2(bar_width(), ENTRY_H), Sense::hover());
    let rect = snap(ui, rect);
    ui.painter().rect_filled(rect, 0.0, ENTRY_BG);
    bevel(ui, rect, DARK, BRIGHT);
    let inner = rect.shrink(3.0);
    let filled = ((count as f32) * progress.clamp(0.0, 1.0)).floor() as usize;
    let p = ui.painter();
    for i in 0..filled {
        let x = inner.min.x + i as f32 * step;
        let outer = snap(ui, Rect::from_min_max(pos2(x, inner.min.y), pos2(x + SEG, inner.max.y)));
        p.rect_filled(outer, 0.0, MAIZE);
    }
    if let Some(s) = label {
        p.text(rect.center(), Align2::CENTER_CENTER, s, font(), TEXT);
    }
}

enum Title {
    Nothing,
    Close,
    Minimize,
    Icon,
}

fn title_bar(
    ui: &mut egui::Ui,
    rect: Rect,
    text: &str,
    icon: Option<&egui::TextureHandle>,
    minimize: bool,
) -> Title {
    let mut out = Title::Nothing;
    let drag = ui.interact(rect, ui.scope_id().with("drag"), Sense::click_and_drag());
    if drag.drag_started() {
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
    }
    let focused = ui.ctx().input(|i| i.viewport().focused).unwrap_or(true);
    let color = if focused { Color32::WHITE } else { BRIGHT };
    let mut x = rect.min.x + 6.0;
    if let Some(t) = icon {
        let r = snap(
            ui,
            Rect::from_min_size(pos2(x, rect.center().y - 8.0), vec2(16.0, 16.0)),
        );
        let uv = Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0));
        ui.painter().image(t.id(), r, uv, Color32::WHITE);
        let resp = ui
            .interact(r, ui.scope_id().with("icon"), Sense::click())
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        if resp.clicked() {
            out = Title::Icon;
        }
        x += 16.0 + 5.0;
    }
    ui.painter()
        .text(pos2(x, rect.center().y), Align2::LEFT_CENTER, text, bold(), color);
    let s = 16.0;
    let y = rect.center().y - s / 2.0;
    let close = Rect::from_min_size(pos2(rect.max.x - 6.0 - s, y), vec2(s, s));
    if title_button(ui, close, true) {
        out = Title::Close;
    }
    if minimize && title_button(ui, close.translate(vec2(-s - 2.0, 0.0)), false) {
        out = Title::Minimize;
    }
    out
}

const VERSION: &str = concat!(env!("CARGO_PKG_VERSION_MAJOR"), ".", env!("CARGO_PKG_VERSION_MINOR"));
const BUILT: &str = env!("BUILD_DATE");
const LOGO: f32 = 64.0;

fn about_ui(ui: &mut egui::Ui, icon: Option<&egui::TextureHandle>, open: &mut bool) {
    if ui.input(|i| i.viewport().close_requested() || i.key_pressed(egui::Key::Escape)) {
        *open = false;
    }
    egui::CentralPanel::default()
        .frame(egui::Frame::NONE.fill(BG))
        .show(ui, |ui| {
            let full = snap(ui, ui.max_rect());
            bevel(ui, full, BRIGHT, DARK);
            let drag = ui.interact(full, ui.scope_id().with("drag"), Sense::click_and_drag());
            if drag.drag_started() {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }
            let content = full.shrink(PAD);
            let logo = snap(
                ui,
                Rect::from_min_size(
                    pos2(content.min.x, content.center().y - LOGO / 2.0),
                    vec2(LOGO, LOGO),
                ),
            );
            if let Some(t) = icon {
                let uv = Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0));
                ui.painter().image(t.id(), logo, uv, Color32::WHITE);
            }
            let lines = [
                ("jack9 by arc".to_string(), bold(), TEXT),
                (format!("version {VERSION}"), font(), DIM),
                (format!("built {BUILT}"), font(), DIM),
            ];
            let widest = lines
                .iter()
                .map(|(t, f, c)| ui.painter().layout_no_wrap(t.clone(), f.clone(), *c).size().x)
                .fold(button_width(ui, "Close"), f32::max);
            let want = vec2((PAD + LOGO + 14.0 + widest + PAD).ceil(), full.height());
            let have = ui.ctx().input(|i| i.viewport().inner_rect).map(|r| r.size());
            if have.is_none_or(|h| (h.x - want.x).abs() > 0.5) {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::InnerSize(want));
            }
            let lh = 16.0;
            let mut y = content.min.y;
            for (t, f, c) in lines {
                ui.painter()
                    .text(pos2(logo.max.x + 14.0, y), Align2::LEFT_TOP, t, f, c);
                y += lh;
            }
            let bw = button_width(ui, "Close");
            let r = Rect::from_min_size(
                pos2(logo.max.x + 14.0, content.max.y - BUTTON_H),
                vec2(bw, BUTTON_H),
            );
            ui.scope_builder(egui::UiBuilder::new().max_rect(r), |ui| {
                if button(ui, "Close", true).clicked() {
                    *open = false;
                }
            });
        });
}

fn setup(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let dir = Path::new(r"C:\Windows\Fonts");
    let regular = fs::read(dir.join("tahoma.ttf")).ok();
    let heavy = fs::read(dir.join("tahomabd.ttf")).ok().or_else(|| regular.clone());
    if let Some(d) = regular {
        fonts
            .font_data
            .insert("tahoma".into(), Arc::new(FontData::from_owned(d)));
        if let Some(f) = fonts.families.get_mut(&FontFamily::Proportional) {
            f.insert(0, "tahoma".into());
        }
    }
    let mut chain = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    if let Some(d) = heavy {
        fonts
            .font_data
            .insert("tahoma-bold".into(), Arc::new(FontData::from_owned(d)));
        chain.insert(0, "tahoma-bold".into());
    }
    fonts.families.insert(FontFamily::Name("bold".into()), chain);
    ctx.set_fonts(fonts);

    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = BG;
    v.extreme_bg_color = ENTRY_BG;
    v.selection.bg_fill = SELECTION;
    v.selection.stroke = Stroke::new(1.0, Color32::WHITE);
    v.text_cursor.stroke = Stroke::new(1.0, TEXT);
    v.override_text_color = Some(TEXT);
    ctx.set_visuals(v);
}

struct App {
    path: String,
    status: String,
    error: bool,
    patched: Option<bool>,
    fill_from: Option<f64>,
    icon: Option<egui::TextureHandle>,
    about: bool,
    about_pos: egui::Pos2,
}

impl App {
    fn new(ctx: &egui::Context) -> Self {
        let icon = eframe::icon_data::from_png_bytes(include_bytes!("../icon.png"))
            .ok()
            .map(|i| {
                let img = egui::ColorImage::from_rgba_unmultiplied(
                    [i.width as usize, i.height as usize],
                    &i.rgba,
                );
                let opts = egui::TextureOptions {
                    mipmap_mode: Some(egui::TextureFilter::Linear),
                    ..egui::TextureOptions::LINEAR
                };
                ctx.load_texture("icon", img, opts)
            });
        let path = find_jack()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let mut app = App {
            path,
            status: String::new(),
            error: false,
            patched: None,
            fill_from: None,
            icon,
            about: false,
            about_pos: egui::Pos2::ZERO,
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        self.error = false;
        self.fill_from = None;
        self.status.clear();
        self.patched = None;
        if self.path.is_empty() {
            return;
        }
        match plugin_patched(Path::new(&self.path)) {
            Ok(b) => self.patched = Some(b),
            Err(e) => self.status = e,
        }
    }

    fn fail(&mut self, e: String) {
        self.patched = None;
        self.fill_from = None;
        self.status = e;
        self.error = true;
    }

    fn has_backup(&self) -> bool {
        dll_for(Path::new(&self.path)).is_some_and(|d| backup_path(&d).is_file())
    }

    fn browse(&mut self) {
        let mut dlg = rfd::FileDialog::new().add_filter("jack.exe", &["exe"]);
        if let Some(dir) = Path::new(&self.path).parent().filter(|d| d.is_dir()) {
            dlg = dlg.set_directory(dir);
        }
        if let Some(p) = dlg.pick_file() {
            self.path = p.display().to_string();
            self.refresh();
        }
    }

    fn body(&mut self, ui: &mut egui::Ui) {
        ui.spacing_mut().item_spacing = vec2(6.0, 0.0);
        let sp = ui.spacing().item_spacing.x;
        let cw = bar_width() + sp + button_width(ui, "Browse...");
        ui.horizontal(|ui| {
            if entry(ui, &mut self.path, bar_width()).changed() {
                self.refresh();
            }
            if button(ui, "Browse...", true).clicked() {
                self.browse();
            }
        });
        ui.add_space(8.0);
        match self.patched {
            Some(patched) => {
                let now = ui.input(|i| i.time);
                let progress = match self.fill_from {
                    Some(t) => {
                        let f = ((now - t) / FILL_SECS).min(1.0) as f32;
                        if f < 1.0 {
                            ui.ctx().request_repaint();
                        }
                        f
                    }
                    None if patched => 1.0,
                    None => 0.0,
                };
                ui.horizontal(|ui| {
                    progress_bar(ui, progress, None);
                    let word = match (patched, progress >= 1.0) {
                        (true, true) => Some("Patched!"),
                        (false, _) => Some("Unpatched!"),
                        _ => None,
                    };
                    if let Some(w) = word {
                        ui.label(RichText::new(w).font(font()).color(TEXT));
                    }
                });
            }
            None => {
                let color = if self.error { ERROR } else { TEXT };
                ui.add_sized(
                    [cw, ENTRY_H],
                    egui::Label::new(RichText::new(&self.status).font(font()).color(color)),
                );
            }
        }
        ui.add_space(PAD);
        divider(ui, cw);
        ui.add_space(PAD);
        ui.horizontal(|ui| {
            let exe = PathBuf::from(&self.path);
            let bws: f32 = ["Patch", "Unpatch", "Restore"]
                .iter()
                .map(|n| button_width(ui, n))
                .sum::<f32>()
                + 2.0 * sp;
            let tw = cw - bws - 2.0 * sp;
            ui.allocate_ui_with_layout(
                vec2(tw, BUTTON_H),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.set_width(tw);
                    ui.add(
                        egui::Label::new(
                            RichText::new("Increases J.A.C.K.'s brush precision to 9 digits (stock is 6).")
                                .font(font())
                                .color(DIM),
                        )
                        .wrap(),
                    );
                },
            );
            ui.add_space(sp);
            let patch_clicked = button(ui, "Patch", dll_for(&exe).is_some()).clicked();
            let unpatch_clicked = button(ui, "Unpatch", self.patched == Some(true)).clicked();
            let restore_clicked = button(ui, "Restore", self.has_backup()).clicked();
            if restore_clicked {
                match do_restore(&exe) {
                    Ok(_) => self.refresh(),
                    Err(e) => self.fail(e),
                }
            }
            if unpatch_clicked {
                match do_unpatch(&exe) {
                    Ok(_) => self.refresh(),
                    Err(e) => self.fail(e),
                }
            }
            if patch_clicked {
                match do_patch(&exe) {
                    Ok(_) => {
                        self.error = false;
                        self.patched = Some(true);
                        self.fill_from = Some(ui.input(|i| i.time));
                    }
                    Err(e) => self.fail(e),
                }
            }
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(BG))
            .show(ui, |ui| {
                let full = snap(ui, ui.max_rect());
                bevel(ui, full, BRIGHT, DARK);
                let title = Rect::from_min_max(full.min, pos2(full.max.x, full.min.y + TITLE_H));
                match title_bar(ui, title, "jack9", self.icon.as_ref(), true) {
                    Title::Close => ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close),
                    Title::Minimize => {
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Minimized(true))
                    }
                    Title::Icon => {
                        let at = ui.ctx().input(|i| i.viewport().outer_rect);
                        self.about_pos = at.map_or(pos2(200.0, 200.0), |r| r.min + vec2(60.0, 30.0));
                        self.about = true;
                    }
                    Title::Nothing => {}
                }
                let inner = Rect::from_min_max(
                    pos2(full.min.x + PAD, title.max.y + 4.0),
                    pos2(full.max.x - PAD, full.max.y - PAD),
                );
                let body = ui
                    .scope_builder(egui::UiBuilder::new().max_rect(inner), |ui| self.body(ui))
                    .response
                    .rect;
                let want = vec2(
                    (body.width() + 2.0 * PAD).round(),
                    (body.max.y - full.min.y + PAD).round(),
                );
                let have = ui.ctx().input(|i| i.viewport().inner_rect).map(|r| r.size());
                if have.is_none_or(|h| (h - want).length() > 0.5) {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::InnerSize(want));
                }
            });
        if self.about {
            let icon = self.icon.clone();
            let mut open = true;
            let builder = egui::ViewportBuilder::default()
                .with_title("about")
                .with_inner_size([220.0, 98.0])
                .with_position(self.about_pos)
                .with_resizable(false)
                .with_decorations(false);
            ui.ctx().show_viewport_immediate(
                egui::ViewportId::from_hash_of("about"),
                builder,
                |ui, _| about_ui(ui, icon.as_ref(), &mut open),
            );
            self.about = open;
        }
    }
}

fn main() -> eframe::Result {
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../icon.png")).ok();
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("jack9")
        .with_inner_size([476.0, 168.0])
        .with_resizable(false)
        .with_decorations(false);
    if let Some(i) = icon {
        viewport = viewport.with_icon(i);
    }
    let options = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native(
        "jack9",
        options,
        Box::new(|cc| {
            setup(&cc.egui_ctx);
            Ok(Box::new(App::new(&cc.egui_ctx)))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patches_original() {
        let p = r"G:\SteamLibrary\steamapps\common\JACK\plugins\vpHalfLifex64.dll.orig";
        let Ok(orig) = fs::read(p) else { return };
        let mut d = orig.clone();
        patch(&mut d).unwrap();
        assert!(matches!(inspect(&d).unwrap(), State::Patched));
        let cur = fs::read(r"G:\SteamLibrary\steamapps\common\JACK\plugins\vpHalfLifex64.dll").unwrap();
        assert_eq!(d, cur);
        assert!(patch(&mut d).is_err());
        let mut u = d.clone();
        unpatch(&mut u).unwrap();
        assert!(matches!(inspect(&u).unwrap(), State::Original { .. }));
        assert!(unpatch(&mut u.clone()).is_err());
        patch(&mut u).unwrap();
        assert_eq!(u, d);
    }
}
